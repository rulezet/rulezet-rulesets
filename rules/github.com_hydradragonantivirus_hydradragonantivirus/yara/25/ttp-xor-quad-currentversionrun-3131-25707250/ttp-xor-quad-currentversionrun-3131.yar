rule TTP_XOR_QUAD_CurrentVersionRun_3131 {
  strings:
    $key_3131 = { 62 5e [2] 46 50 [2] 6d 7c [2] 43 5e [2] 57 45 [2] 58 5f [2] 46 42 [2] 44 43 [2] 5f 45 [2] 43 42 [2] 5f 6d }

  condition:
    any of them
}