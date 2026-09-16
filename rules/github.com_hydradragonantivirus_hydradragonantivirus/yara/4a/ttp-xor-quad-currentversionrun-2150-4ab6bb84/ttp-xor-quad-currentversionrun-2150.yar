rule TTP_XOR_QUAD_CurrentVersionRun_2150 {
  strings:
    $key_2150 = { 72 3f [2] 56 31 [2] 7d 1d [2] 53 3f [2] 47 24 [2] 48 3e [2] 56 23 [2] 54 22 [2] 4f 24 [2] 53 23 [2] 4f 0c }

  condition:
    any of them
}