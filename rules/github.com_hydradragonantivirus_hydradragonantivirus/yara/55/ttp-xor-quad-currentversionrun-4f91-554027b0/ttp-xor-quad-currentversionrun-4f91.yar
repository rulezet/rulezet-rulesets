rule TTP_XOR_QUAD_CurrentVersionRun_4f91 {
  strings:
    $key_4f91 = { 1c fe [2] 38 f0 [2] 13 dc [2] 3d fe [2] 29 e5 [2] 26 ff [2] 38 e2 [2] 3a e3 [2] 21 e5 [2] 3d e2 [2] 21 cd }

  condition:
    any of them
}