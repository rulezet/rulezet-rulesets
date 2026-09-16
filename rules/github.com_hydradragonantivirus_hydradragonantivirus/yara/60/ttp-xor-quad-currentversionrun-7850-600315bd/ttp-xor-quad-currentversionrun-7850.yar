rule TTP_XOR_QUAD_CurrentVersionRun_7850 {
  strings:
    $key_7850 = { 2b 3f [2] 0f 31 [2] 24 1d [2] 0a 3f [2] 1e 24 [2] 11 3e [2] 0f 23 [2] 0d 22 [2] 16 24 [2] 0a 23 [2] 16 0c }

  condition:
    any of them
}