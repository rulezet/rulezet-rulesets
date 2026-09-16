rule TTP_XOR_QUAD_CurrentVersionRun_7320 {
  strings:
    $key_7320 = { 20 4f [2] 04 41 [2] 2f 6d [2] 01 4f [2] 15 54 [2] 1a 4e [2] 04 53 [2] 06 52 [2] 1d 54 [2] 01 53 [2] 1d 7c }

  condition:
    any of them
}