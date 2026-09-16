rule TTP_XOR_QUAD_CurrentVersionRun_6d60 {
  strings:
    $key_6d60 = { 3e 0f [2] 1a 01 [2] 31 2d [2] 1f 0f [2] 0b 14 [2] 04 0e [2] 1a 13 [2] 18 12 [2] 03 14 [2] 1f 13 [2] 03 3c }

  condition:
    any of them
}