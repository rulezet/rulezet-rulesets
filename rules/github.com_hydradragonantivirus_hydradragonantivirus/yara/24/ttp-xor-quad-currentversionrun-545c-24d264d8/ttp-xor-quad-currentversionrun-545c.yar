rule TTP_XOR_QUAD_CurrentVersionRun_545c {
  strings:
    $key_545c = { 07 33 [2] 23 3d [2] 08 11 [2] 26 33 [2] 32 28 [2] 3d 32 [2] 23 2f [2] 21 2e [2] 3a 28 [2] 26 2f [2] 3a 00 }

  condition:
    any of them
}