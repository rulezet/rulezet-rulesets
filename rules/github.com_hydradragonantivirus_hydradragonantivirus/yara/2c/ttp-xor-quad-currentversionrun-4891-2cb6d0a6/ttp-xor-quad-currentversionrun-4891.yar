rule TTP_XOR_QUAD_CurrentVersionRun_4891 {
  strings:
    $key_4891 = { 1b fe [2] 3f f0 [2] 14 dc [2] 3a fe [2] 2e e5 [2] 21 ff [2] 3f e2 [2] 3d e3 [2] 26 e5 [2] 3a e2 [2] 26 cd }

  condition:
    any of them
}