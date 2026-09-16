rule TTP_XOR_QUAD_CurrentVersionRun_6691 {
  strings:
    $key_6691 = { 35 fe [2] 11 f0 [2] 3a dc [2] 14 fe [2] 00 e5 [2] 0f ff [2] 11 e2 [2] 13 e3 [2] 08 e5 [2] 14 e2 [2] 08 cd }

  condition:
    any of them
}