rule TTP_XOR_QUAD_CurrentVersionRun_7c90 {
  strings:
    $key_7c90 = { 2f ff [2] 0b f1 [2] 20 dd [2] 0e ff [2] 1a e4 [2] 15 fe [2] 0b e3 [2] 09 e2 [2] 12 e4 [2] 0e e3 [2] 12 cc }

  condition:
    any of them
}