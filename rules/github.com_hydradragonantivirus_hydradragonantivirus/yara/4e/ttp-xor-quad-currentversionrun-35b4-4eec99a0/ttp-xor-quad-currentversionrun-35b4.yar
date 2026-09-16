rule TTP_XOR_QUAD_CurrentVersionRun_35b4 {
  strings:
    $key_35b4 = { 66 db [2] 42 d5 [2] 69 f9 [2] 47 db [2] 53 c0 [2] 5c da [2] 42 c7 [2] 40 c6 [2] 5b c0 [2] 47 c7 [2] 5b e8 }

  condition:
    any of them
}