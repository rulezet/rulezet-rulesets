rule TTP_XOR_QUAD_CurrentVersionRun_7d60 {
  strings:
    $key_7d60 = { 2e 0f [2] 0a 01 [2] 21 2d [2] 0f 0f [2] 1b 14 [2] 14 0e [2] 0a 13 [2] 08 12 [2] 13 14 [2] 0f 13 [2] 13 3c }

  condition:
    any of them
}