rule TTP_XOR_QUAD_CurrentVersionRun_0f91 {
  strings:
    $key_0f91 = { 5c fe [2] 78 f0 [2] 53 dc [2] 7d fe [2] 69 e5 [2] 66 ff [2] 78 e2 [2] 7a e3 [2] 61 e5 [2] 7d e2 [2] 61 cd }

  condition:
    any of them
}