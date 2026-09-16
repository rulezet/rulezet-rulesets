rule TTP_XOR_QUAD_CurrentVersionRun_4d91 {
  strings:
    $key_4d91 = { 1e fe [2] 3a f0 [2] 11 dc [2] 3f fe [2] 2b e5 [2] 24 ff [2] 3a e2 [2] 38 e3 [2] 23 e5 [2] 3f e2 [2] 23 cd }

  condition:
    any of them
}