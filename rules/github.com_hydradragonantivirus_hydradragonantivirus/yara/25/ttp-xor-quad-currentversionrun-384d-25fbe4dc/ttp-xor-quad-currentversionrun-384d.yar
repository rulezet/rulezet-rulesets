rule TTP_XOR_QUAD_CurrentVersionRun_384d {
  strings:
    $key_384d = { 6b 22 [2] 4f 2c [2] 64 00 [2] 4a 22 [2] 5e 39 [2] 51 23 [2] 4f 3e [2] 4d 3f [2] 56 39 [2] 4a 3e [2] 56 11 }

  condition:
    any of them
}