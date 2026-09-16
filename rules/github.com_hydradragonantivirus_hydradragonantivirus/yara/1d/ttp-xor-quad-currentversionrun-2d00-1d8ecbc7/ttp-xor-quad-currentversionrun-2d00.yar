rule TTP_XOR_QUAD_CurrentVersionRun_2d00 {
  strings:
    $key_2d00 = { 7e 6f [2] 5a 61 [2] 71 4d [2] 5f 6f [2] 4b 74 [2] 44 6e [2] 5a 73 [2] 58 72 [2] 43 74 [2] 5f 73 [2] 43 5c }

  condition:
    any of them
}