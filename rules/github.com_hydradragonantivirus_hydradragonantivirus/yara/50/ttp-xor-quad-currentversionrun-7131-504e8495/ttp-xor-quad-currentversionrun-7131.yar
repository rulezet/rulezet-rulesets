rule TTP_XOR_QUAD_CurrentVersionRun_7131 {
  strings:
    $key_7131 = { 22 5e [2] 06 50 [2] 2d 7c [2] 03 5e [2] 17 45 [2] 18 5f [2] 06 42 [2] 04 43 [2] 1f 45 [2] 03 42 [2] 1f 6d }

  condition:
    any of them
}