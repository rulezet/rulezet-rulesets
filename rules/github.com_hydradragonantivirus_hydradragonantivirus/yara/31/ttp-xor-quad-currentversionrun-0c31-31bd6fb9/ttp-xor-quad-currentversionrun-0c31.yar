rule TTP_XOR_QUAD_CurrentVersionRun_0c31 {
  strings:
    $key_0c31 = { 5f 5e [2] 7b 50 [2] 50 7c [2] 7e 5e [2] 6a 45 [2] 65 5f [2] 7b 42 [2] 79 43 [2] 62 45 [2] 7e 42 [2] 62 6d }

  condition:
    any of them
}