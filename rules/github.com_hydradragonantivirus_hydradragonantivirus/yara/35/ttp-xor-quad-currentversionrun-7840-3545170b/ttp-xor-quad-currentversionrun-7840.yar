rule TTP_XOR_QUAD_CurrentVersionRun_7840 {
  strings:
    $key_7840 = { 2b 2f [2] 0f 21 [2] 24 0d [2] 0a 2f [2] 1e 34 [2] 11 2e [2] 0f 33 [2] 0d 32 [2] 16 34 [2] 0a 33 [2] 16 1c }

  condition:
    any of them
}