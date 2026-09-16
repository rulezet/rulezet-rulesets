rule TTP_XOR_QUAD_CurrentVersionRun_f991 {
  strings:
    $key_f991 = { aa fe [2] 8e f0 [2] a5 dc [2] 8b fe [2] 9f e5 [2] 90 ff [2] 8e e2 [2] 8c e3 [2] 97 e5 [2] 8b e2 [2] 97 cd }

  condition:
    any of them
}