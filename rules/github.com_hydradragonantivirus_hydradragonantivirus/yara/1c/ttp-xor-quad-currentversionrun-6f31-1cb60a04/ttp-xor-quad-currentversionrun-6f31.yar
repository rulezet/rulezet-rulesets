rule TTP_XOR_QUAD_CurrentVersionRun_6f31 {
  strings:
    $key_6f31 = { 3c 5e [2] 18 50 [2] 33 7c [2] 1d 5e [2] 09 45 [2] 06 5f [2] 18 42 [2] 1a 43 [2] 01 45 [2] 1d 42 [2] 01 6d }

  condition:
    any of them
}