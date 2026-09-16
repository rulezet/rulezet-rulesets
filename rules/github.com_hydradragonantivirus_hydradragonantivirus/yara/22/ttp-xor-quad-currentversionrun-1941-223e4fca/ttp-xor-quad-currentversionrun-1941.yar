rule TTP_XOR_QUAD_CurrentVersionRun_1941 {
  strings:
    $key_1941 = { 4a 2e [2] 6e 20 [2] 45 0c [2] 6b 2e [2] 7f 35 [2] 70 2f [2] 6e 32 [2] 6c 33 [2] 77 35 [2] 6b 32 [2] 77 1d }

  condition:
    any of them
}