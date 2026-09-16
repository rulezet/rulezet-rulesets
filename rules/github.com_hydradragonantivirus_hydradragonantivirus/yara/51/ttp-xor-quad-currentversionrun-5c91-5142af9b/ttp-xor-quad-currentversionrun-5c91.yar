rule TTP_XOR_QUAD_CurrentVersionRun_5c91 {
  strings:
    $key_5c91 = { 0f fe [2] 2b f0 [2] 00 dc [2] 2e fe [2] 3a e5 [2] 35 ff [2] 2b e2 [2] 29 e3 [2] 32 e5 [2] 2e e2 [2] 32 cd }

  condition:
    any of them
}