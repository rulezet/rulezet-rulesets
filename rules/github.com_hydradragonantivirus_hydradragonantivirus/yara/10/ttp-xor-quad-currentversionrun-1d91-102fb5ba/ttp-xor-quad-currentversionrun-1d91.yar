rule TTP_XOR_QUAD_CurrentVersionRun_1d91 {
  strings:
    $key_1d91 = { 4e fe [2] 6a f0 [2] 41 dc [2] 6f fe [2] 7b e5 [2] 74 ff [2] 6a e2 [2] 68 e3 [2] 73 e5 [2] 6f e2 [2] 73 cd }

  condition:
    any of them
}