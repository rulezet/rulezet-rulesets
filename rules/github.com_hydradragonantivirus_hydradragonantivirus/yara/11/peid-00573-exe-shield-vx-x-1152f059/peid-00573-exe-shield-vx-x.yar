rule PEiD_00573_Exe_Shield_vx_x_ {
  meta:
    description = "[Exe Shield vx.x]"
    ep_only     = "true"

  strings:
    $a = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

  condition:
    $a
}