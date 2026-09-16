rule TTP_XOR_QUAD_CurrentVersionRun_4991 {
  strings:
    $key_4991 = { 1a fe [2] 3e f0 [2] 15 dc [2] 3b fe [2] 2f e5 [2] 20 ff [2] 3e e2 [2] 3c e3 [2] 27 e5 [2] 3b e2 [2] 27 cd }

  condition:
    any of them
}