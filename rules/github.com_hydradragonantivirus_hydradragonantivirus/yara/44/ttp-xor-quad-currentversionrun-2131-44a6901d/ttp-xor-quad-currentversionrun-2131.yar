rule TTP_XOR_QUAD_CurrentVersionRun_2131 {
  strings:
    $key_2131 = { 72 5e [2] 56 50 [2] 7d 7c [2] 53 5e [2] 47 45 [2] 48 5f [2] 56 42 [2] 54 43 [2] 4f 45 [2] 53 42 [2] 4f 6d }

  condition:
    any of them
}