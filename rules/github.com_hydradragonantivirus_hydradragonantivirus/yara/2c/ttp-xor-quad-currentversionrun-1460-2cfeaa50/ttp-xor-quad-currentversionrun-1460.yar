rule TTP_XOR_QUAD_CurrentVersionRun_1460 {
  strings:
    $key_1460 = { 47 0f [2] 63 01 [2] 48 2d [2] 66 0f [2] 72 14 [2] 7d 0e [2] 63 13 [2] 61 12 [2] 7a 14 [2] 66 13 [2] 7a 3c }

  condition:
    any of them
}