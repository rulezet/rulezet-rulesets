rule TTP_XOR_QUAD_CurrentVersionRun_6560 {
  strings:
    $key_6560 = { 36 0f [2] 12 01 [2] 39 2d [2] 17 0f [2] 03 14 [2] 0c 0e [2] 12 13 [2] 10 12 [2] 0b 14 [2] 17 13 [2] 0b 3c }

  condition:
    any of them
}