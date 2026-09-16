rule TTP_XOR_QUAD_CurrentVersionRun_5f00 {
  strings:
    $key_5f00 = { 0c 6f [2] 28 61 [2] 03 4d [2] 2d 6f [2] 39 74 [2] 36 6e [2] 28 73 [2] 2a 72 [2] 31 74 [2] 2d 73 [2] 31 5c }

  condition:
    any of them
}