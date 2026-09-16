rule TTP_XOR_QUAD_CurrentVersionRun_7991 {
  strings:
    $key_7991 = { 2a fe [2] 0e f0 [2] 25 dc [2] 0b fe [2] 1f e5 [2] 10 ff [2] 0e e2 [2] 0c e3 [2] 17 e5 [2] 0b e2 [2] 17 cd }

  condition:
    any of them
}