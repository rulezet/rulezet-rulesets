rule TTP_XOR_QUAD_CurrentVersionRun_1c90 {
  strings:
    $key_1c90 = { 4f ff [2] 6b f1 [2] 40 dd [2] 6e ff [2] 7a e4 [2] 75 fe [2] 6b e3 [2] 69 e2 [2] 72 e4 [2] 6e e3 [2] 72 cc }

  condition:
    any of them
}