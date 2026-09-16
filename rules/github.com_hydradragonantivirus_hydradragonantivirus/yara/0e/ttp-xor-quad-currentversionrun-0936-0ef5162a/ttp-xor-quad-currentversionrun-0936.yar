rule TTP_XOR_QUAD_CurrentVersionRun_0936 {
  strings:
    $key_0936 = { 5a 59 [2] 7e 57 [2] 55 7b [2] 7b 59 [2] 6f 42 [2] 60 58 [2] 7e 45 [2] 7c 44 [2] 67 42 [2] 7b 45 [2] 67 6a }

  condition:
    any of them
}