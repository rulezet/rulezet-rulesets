rule TTP_XOR_QUAD_CurrentVersionRun_5f91 {
  strings:
    $key_5f91 = { 0c fe [2] 28 f0 [2] 03 dc [2] 2d fe [2] 39 e5 [2] 36 ff [2] 28 e2 [2] 2a e3 [2] 31 e5 [2] 2d e2 [2] 31 cd }

  condition:
    any of them
}