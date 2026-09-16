rule TTP_XOR_QUAD_CurrentVersionRun_1d31 {
  strings:
    $key_1d31 = { 4e 5e [2] 6a 50 [2] 41 7c [2] 6f 5e [2] 7b 45 [2] 74 5f [2] 6a 42 [2] 68 43 [2] 73 45 [2] 6f 42 [2] 73 6d }

  condition:
    any of them
}