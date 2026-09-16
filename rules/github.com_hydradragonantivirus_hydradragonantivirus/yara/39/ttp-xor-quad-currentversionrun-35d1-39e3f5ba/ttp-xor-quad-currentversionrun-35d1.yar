rule TTP_XOR_QUAD_CurrentVersionRun_35d1 {
  strings:
    $key_35d1 = { 66 be [2] 42 b0 [2] 69 9c [2] 47 be [2] 53 a5 [2] 5c bf [2] 42 a2 [2] 40 a3 [2] 5b a5 [2] 47 a2 [2] 5b 8d }

  condition:
    any of them
}