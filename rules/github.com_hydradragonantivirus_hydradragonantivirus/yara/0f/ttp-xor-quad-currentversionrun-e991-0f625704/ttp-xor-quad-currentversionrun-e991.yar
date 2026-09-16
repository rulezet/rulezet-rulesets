rule TTP_XOR_QUAD_CurrentVersionRun_e991 {
  strings:
    $key_e991 = { ba fe [2] 9e f0 [2] b5 dc [2] 9b fe [2] 8f e5 [2] 80 ff [2] 9e e2 [2] 9c e3 [2] 87 e5 [2] 9b e2 [2] 87 cd }

  condition:
    any of them
}