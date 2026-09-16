rule TTP_XOR_QUAD_CurrentVersionRun_5100 {
  strings:
    $key_5100 = { 02 6f [2] 26 61 [2] 0d 4d [2] 23 6f [2] 37 74 [2] 38 6e [2] 26 73 [2] 24 72 [2] 3f 74 [2] 23 73 [2] 3f 5c }

  condition:
    any of them
}