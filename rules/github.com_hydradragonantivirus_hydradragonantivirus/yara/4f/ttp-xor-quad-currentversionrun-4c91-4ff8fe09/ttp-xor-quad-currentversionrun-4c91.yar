rule TTP_XOR_QUAD_CurrentVersionRun_4c91 {
  strings:
    $key_4c91 = { 1f fe [2] 3b f0 [2] 10 dc [2] 3e fe [2] 2a e5 [2] 25 ff [2] 3b e2 [2] 39 e3 [2] 22 e5 [2] 3e e2 [2] 22 cd }

  condition:
    any of them
}