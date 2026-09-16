rule TTP_XOR_QUAD_CurrentVersionRun_533f {
  strings:
    $key_533f = { 00 50 [2] 24 5e [2] 0f 72 [2] 21 50 [2] 35 4b [2] 3a 51 [2] 24 4c [2] 26 4d [2] 3d 4b [2] 21 4c [2] 3d 63 }

  condition:
    any of them
}