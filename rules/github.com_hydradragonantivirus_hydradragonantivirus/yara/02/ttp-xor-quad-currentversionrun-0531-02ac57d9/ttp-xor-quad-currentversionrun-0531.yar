rule TTP_XOR_QUAD_CurrentVersionRun_0531 {
  strings:
    $key_0531 = { 56 5e [2] 72 50 [2] 59 7c [2] 77 5e [2] 63 45 [2] 6c 5f [2] 72 42 [2] 70 43 [2] 6b 45 [2] 77 42 [2] 6b 6d }

  condition:
    any of them
}