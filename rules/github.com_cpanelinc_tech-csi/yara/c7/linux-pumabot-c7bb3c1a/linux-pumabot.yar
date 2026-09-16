rule Linux_PumaBot {
  meta:
      description = "Rule to match on PumaBot samples"
      author = "tgould@cadosecurity.com"
  strings:
      $xapikey = "X-API-KEY" ascii
      $get_ips = "?count=5000" ascii
      $exec_start = "ExecStart=/lib/redis" ascii
      $svc_name1 = "redis.service" ascii
      $svc_name2 = "mysqI.service" ascii
      $uname = "uname -a" ascii
      $pumatronix = "Pumatronix" ascii
  condition:
      uint32(0) == 0x464c457f and
      all of (
          $xapikey,
          $uname,
          $get_ips,
          $exec_start
      ) and any of (
          $svc_name1,
          $svc_name2
      ) and $pumatronix
}