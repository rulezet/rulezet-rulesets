rule TTP_XOR_QUAD_CurrentVersionRun_5a7f {
  strings:
    $key_5a7f = { 09 10 [2] 2d 1e [2] 06 32 [2] 28 10 [2] 3c 0b [2] 33 11 [2] 2d 0c [2] 2f 0d [2] 34 0b [2] 28 0c [2] 34 23 }

  condition:
    any of them
}