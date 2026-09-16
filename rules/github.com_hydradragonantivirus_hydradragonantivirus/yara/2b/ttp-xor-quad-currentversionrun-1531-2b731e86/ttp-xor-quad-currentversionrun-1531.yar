rule TTP_XOR_QUAD_CurrentVersionRun_1531 {
  strings:
    $key_1531 = { 46 5e [2] 62 50 [2] 49 7c [2] 67 5e [2] 73 45 [2] 7c 5f [2] 62 42 [2] 60 43 [2] 7b 45 [2] 67 42 [2] 7b 6d }

  condition:
    any of them
}