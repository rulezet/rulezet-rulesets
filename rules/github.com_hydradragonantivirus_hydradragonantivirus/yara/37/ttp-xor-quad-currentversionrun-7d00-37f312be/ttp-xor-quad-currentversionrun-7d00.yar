rule TTP_XOR_QUAD_CurrentVersionRun_7d00 {
  strings:
    $key_7d00 = { 2e 6f [2] 0a 61 [2] 21 4d [2] 0f 6f [2] 1b 74 [2] 14 6e [2] 0a 73 [2] 08 72 [2] 13 74 [2] 0f 73 [2] 13 5c }

  condition:
    any of them
}