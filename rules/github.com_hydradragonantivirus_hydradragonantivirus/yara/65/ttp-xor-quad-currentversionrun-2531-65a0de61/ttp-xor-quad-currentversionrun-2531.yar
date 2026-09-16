rule TTP_XOR_QUAD_CurrentVersionRun_2531 {
  strings:
    $key_2531 = { 76 5e [2] 52 50 [2] 79 7c [2] 57 5e [2] 43 45 [2] 4c 5f [2] 52 42 [2] 50 43 [2] 4b 45 [2] 57 42 [2] 4b 6d }

  condition:
    any of them
}