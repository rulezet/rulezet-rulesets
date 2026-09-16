rule TTP_XOR_QUAD_CurrentVersionRun_7f31 {
  strings:
    $key_7f31 = { 2c 5e [2] 08 50 [2] 23 7c [2] 0d 5e [2] 19 45 [2] 16 5f [2] 08 42 [2] 0a 43 [2] 11 45 [2] 0d 42 [2] 11 6d }

  condition:
    any of them
}