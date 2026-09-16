rule TTP_XOR_QUAD_CurrentVersionRun_034d {
  strings:
    $key_034d = { 50 22 [2] 74 2c [2] 5f 00 [2] 71 22 [2] 65 39 [2] 6a 23 [2] 74 3e [2] 76 3f [2] 6d 39 [2] 71 3e [2] 6d 11 }

  condition:
    any of them
}