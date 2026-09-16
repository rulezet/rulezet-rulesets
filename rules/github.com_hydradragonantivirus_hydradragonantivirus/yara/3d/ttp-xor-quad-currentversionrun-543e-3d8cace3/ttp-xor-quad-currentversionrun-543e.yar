rule TTP_XOR_QUAD_CurrentVersionRun_543e {
  strings:
    $key_543e = { 07 51 [2] 23 5f [2] 08 73 [2] 26 51 [2] 32 4a [2] 3d 50 [2] 23 4d [2] 21 4c [2] 3a 4a [2] 26 4d [2] 3a 62 }

  condition:
    any of them
}