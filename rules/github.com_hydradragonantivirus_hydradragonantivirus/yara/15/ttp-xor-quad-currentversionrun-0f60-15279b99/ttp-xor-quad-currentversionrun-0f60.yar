rule TTP_XOR_QUAD_CurrentVersionRun_0f60 {
  strings:
    $key_0f60 = { 5c 0f [2] 78 01 [2] 53 2d [2] 7d 0f [2] 69 14 [2] 66 0e [2] 78 13 [2] 7a 12 [2] 61 14 [2] 7d 13 [2] 61 3c }

  condition:
    any of them
}