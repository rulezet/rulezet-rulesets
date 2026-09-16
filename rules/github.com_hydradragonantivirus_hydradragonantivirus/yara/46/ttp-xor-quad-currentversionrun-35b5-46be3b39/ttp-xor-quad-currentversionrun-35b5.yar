rule TTP_XOR_QUAD_CurrentVersionRun_35b5 {
  strings:
    $key_35b5 = { 66 da [2] 42 d4 [2] 69 f8 [2] 47 da [2] 53 c1 [2] 5c db [2] 42 c6 [2] 40 c7 [2] 5b c1 [2] 47 c6 [2] 5b e9 }

  condition:
    any of them
}