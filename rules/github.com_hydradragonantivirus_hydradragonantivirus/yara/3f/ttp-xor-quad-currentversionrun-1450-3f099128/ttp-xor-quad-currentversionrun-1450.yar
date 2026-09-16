rule TTP_XOR_QUAD_CurrentVersionRun_1450 {
  strings:
    $key_1450 = { 47 3f [2] 63 31 [2] 48 1d [2] 66 3f [2] 72 24 [2] 7d 3e [2] 63 23 [2] 61 22 [2] 7a 24 [2] 66 23 [2] 7a 0c }

  condition:
    any of them
}