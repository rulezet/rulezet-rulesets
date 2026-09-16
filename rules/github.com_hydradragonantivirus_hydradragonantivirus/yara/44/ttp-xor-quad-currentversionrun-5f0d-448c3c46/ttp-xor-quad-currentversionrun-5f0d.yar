rule TTP_XOR_QUAD_CurrentVersionRun_5f0d {
  strings:
    $key_5f0d = { 0c 62 [2] 28 6c [2] 03 40 [2] 2d 62 [2] 39 79 [2] 36 63 [2] 28 7e [2] 2a 7f [2] 31 79 [2] 2d 7e [2] 31 51 }

  condition:
    any of them
}