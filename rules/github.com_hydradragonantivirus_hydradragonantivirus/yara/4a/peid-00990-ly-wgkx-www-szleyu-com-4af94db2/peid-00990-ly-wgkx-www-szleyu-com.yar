rule PEiD_00990_LY_WGKX____www_szleyu_com_ {
  meta:
    description = "[LY_WGKX -> www.szleyu.com]"
    ep_only     = "false"

  strings:
    $a = { 4D 79 46 75 6E 00 62 73 }

  condition:
    $a
}