rule TTP_XOR_QUAD_CurrentVersionRun_1c00 {
  strings:
    $key_1c00 = { 4f 6f [2] 6b 61 [2] 40 4d [2] 6e 6f [2] 7a 74 [2] 75 6e [2] 6b 73 [2] 69 72 [2] 72 74 [2] 6e 73 [2] 72 5c }

  condition:
    any of them
}