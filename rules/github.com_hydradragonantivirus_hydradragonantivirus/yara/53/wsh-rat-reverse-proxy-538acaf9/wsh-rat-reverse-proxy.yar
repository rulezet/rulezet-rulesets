rule wsh_rat_reverse_proxy {
  meta:
    author      = "jeFF0Falltrades"
    ref         = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
    description = "Alerts on the WSH RAT .NET reverse proxy module"

  strings:
    $str_0 = "RProxy:" wide ascii nocase
    $str_1 = "WSH Inc" wide ascii nocase
    $str_2 = "WSH Reverse Proxy" wide ascii nocase
    $str_3 = "Debug\\ReverseProxy.pdb" wide ascii nocase
    $str_4 = "WshRP" wide ascii nocase
    $str_5 = "NotifyBringNewSocket" wide ascii nocase

  condition:
    3 of them
}