rule TTP_XOR_QUAD_CurrentVersionRun_3e91 {
  strings:
    $key_3e91 = { 6d fe [2] 49 f0 [2] 62 dc [2] 4c fe [2] 58 e5 [2] 57 ff [2] 49 e2 [2] 4b e3 [2] 50 e5 [2] 4c e2 [2] 50 cd }

  condition:
    any of them
}