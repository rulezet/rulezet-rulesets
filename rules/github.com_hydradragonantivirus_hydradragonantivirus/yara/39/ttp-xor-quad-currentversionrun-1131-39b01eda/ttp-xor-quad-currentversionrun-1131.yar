rule TTP_XOR_QUAD_CurrentVersionRun_1131 {
  strings:
    $key_1131 = { 42 5e [2] 66 50 [2] 4d 7c [2] 63 5e [2] 77 45 [2] 78 5f [2] 66 42 [2] 64 43 [2] 7f 45 [2] 63 42 [2] 7f 6d }

  condition:
    any of them
}