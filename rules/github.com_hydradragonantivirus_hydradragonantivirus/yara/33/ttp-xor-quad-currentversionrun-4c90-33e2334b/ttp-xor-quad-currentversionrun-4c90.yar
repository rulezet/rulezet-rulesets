rule TTP_XOR_QUAD_CurrentVersionRun_4c90 {
  strings:
    $key_4c90 = { 1f ff [2] 3b f1 [2] 10 dd [2] 3e ff [2] 2a e4 [2] 25 fe [2] 3b e3 [2] 39 e2 [2] 22 e4 [2] 3e e3 [2] 22 cc }

  condition:
    any of them
}