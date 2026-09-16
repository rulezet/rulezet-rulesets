rule TTP_XOR_QUAD_CurrentVersionRun_2d36 {
  strings:
    $key_2d36 = { 7e 59 [2] 5a 57 [2] 71 7b [2] 5f 59 [2] 4b 42 [2] 44 58 [2] 5a 45 [2] 58 44 [2] 43 42 [2] 5f 45 [2] 43 6a }

  condition:
    any of them
}