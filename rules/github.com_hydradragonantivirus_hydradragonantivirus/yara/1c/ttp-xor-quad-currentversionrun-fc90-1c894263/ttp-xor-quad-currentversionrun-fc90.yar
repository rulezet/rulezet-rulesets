rule TTP_XOR_QUAD_CurrentVersionRun_fc90 {
  strings:
    $key_fc90 = { af ff [2] 8b f1 [2] a0 dd [2] 8e ff [2] 9a e4 [2] 95 fe [2] 8b e3 [2] 89 e2 [2] 92 e4 [2] 8e e3 [2] 92 cc }

  condition:
    any of them
}