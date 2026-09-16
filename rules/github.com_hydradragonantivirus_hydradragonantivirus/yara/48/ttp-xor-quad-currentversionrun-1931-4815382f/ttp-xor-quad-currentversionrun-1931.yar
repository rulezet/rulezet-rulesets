rule TTP_XOR_QUAD_CurrentVersionRun_1931 {
  strings:
    $key_1931 = { 4a 5e [2] 6e 50 [2] 45 7c [2] 6b 5e [2] 7f 45 [2] 70 5f [2] 6e 42 [2] 6c 43 [2] 77 45 [2] 6b 42 [2] 77 6d }

  condition:
    any of them
}