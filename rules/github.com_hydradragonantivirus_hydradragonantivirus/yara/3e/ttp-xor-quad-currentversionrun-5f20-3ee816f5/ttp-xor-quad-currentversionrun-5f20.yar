rule TTP_XOR_QUAD_CurrentVersionRun_5f20 {
  strings:
    $key_5f20 = { 0c 4f [2] 28 41 [2] 03 6d [2] 2d 4f [2] 39 54 [2] 36 4e [2] 28 53 [2] 2a 52 [2] 31 54 [2] 2d 53 [2] 31 7c }

  condition:
    any of them
}