rule PEiD_00653_ExeSmasher_vx_x_ {
  meta:
    description = "[ExeSmasher vx.x]"
    ep_only     = "true"

  strings:
    $a = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }

  condition:
    $a
}