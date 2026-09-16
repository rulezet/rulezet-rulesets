rule TTP_XOR_QUAD_CurrentVersionRun_2936 {
  strings:
    $key_2936 = { 7a 59 [2] 5e 57 [2] 75 7b [2] 5b 59 [2] 4f 42 [2] 40 58 [2] 5e 45 [2] 5c 44 [2] 47 42 [2] 5b 45 [2] 47 6a }

  condition:
    any of them
}