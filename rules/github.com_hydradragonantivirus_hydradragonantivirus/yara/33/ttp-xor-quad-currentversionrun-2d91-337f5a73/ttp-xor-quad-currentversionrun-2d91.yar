rule TTP_XOR_QUAD_CurrentVersionRun_2d91 {
  strings:
    $key_2d91 = { 7e fe [2] 5a f0 [2] 71 dc [2] 5f fe [2] 4b e5 [2] 44 ff [2] 5a e2 [2] 58 e3 [2] 43 e5 [2] 5f e2 [2] 43 cd }

  condition:
    any of them
}