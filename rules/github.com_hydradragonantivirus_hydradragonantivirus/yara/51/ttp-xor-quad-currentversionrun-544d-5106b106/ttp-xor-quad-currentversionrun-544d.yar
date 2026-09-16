rule TTP_XOR_QUAD_CurrentVersionRun_544d {
  strings:
    $key_544d = { 07 22 [2] 23 2c [2] 08 00 [2] 26 22 [2] 32 39 [2] 3d 23 [2] 23 3e [2] 21 3f [2] 3a 39 [2] 26 3e [2] 3a 11 }

  condition:
    any of them
}