rule TTP_XOR_QUAD_CurrentVersionRun_7c21 {
  strings:
    $key_7c21 = { 2f 4e [2] 0b 40 [2] 20 6c [2] 0e 4e [2] 1a 55 [2] 15 4f [2] 0b 52 [2] 09 53 [2] 12 55 [2] 0e 52 [2] 12 7d }

  condition:
    any of them
}