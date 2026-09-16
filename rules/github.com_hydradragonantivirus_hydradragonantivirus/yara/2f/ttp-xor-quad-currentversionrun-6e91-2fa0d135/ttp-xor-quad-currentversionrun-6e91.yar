rule TTP_XOR_QUAD_CurrentVersionRun_6e91 {
  strings:
    $key_6e91 = { 3d fe [2] 19 f0 [2] 32 dc [2] 1c fe [2] 08 e5 [2] 07 ff [2] 19 e2 [2] 1b e3 [2] 00 e5 [2] 1c e2 [2] 00 cd }

  condition:
    any of them
}