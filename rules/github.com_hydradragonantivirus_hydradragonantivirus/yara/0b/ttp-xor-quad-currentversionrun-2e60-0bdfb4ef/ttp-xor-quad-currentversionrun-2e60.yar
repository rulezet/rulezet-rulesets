rule TTP_XOR_QUAD_CurrentVersionRun_2e60 {
  strings:
    $key_2e60 = { 7d 0f [2] 59 01 [2] 72 2d [2] 5c 0f [2] 48 14 [2] 47 0e [2] 59 13 [2] 5b 12 [2] 40 14 [2] 5c 13 [2] 40 3c }

  condition:
    any of them
}