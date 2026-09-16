rule TTP_XOR_QUAD_CurrentVersionRun_6831 {
  strings:
    $key_6831 = { 3b 5e [2] 1f 50 [2] 34 7c [2] 1a 5e [2] 0e 45 [2] 01 5f [2] 1f 42 [2] 1d 43 [2] 06 45 [2] 1a 42 [2] 06 6d }

  condition:
    any of them
}