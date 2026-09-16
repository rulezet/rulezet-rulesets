rule TTP_XOR_QUAD_CurrentVersionRun_7820 {
  strings:
    $key_7820 = { 2b 4f [2] 0f 41 [2] 24 6d [2] 0a 4f [2] 1e 54 [2] 11 4e [2] 0f 53 [2] 0d 52 [2] 16 54 [2] 0a 53 [2] 16 7c }

  condition:
    any of them
}