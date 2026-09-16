rule TTP_XOR_QUAD_CurrentVersionRun_6c90 {
  strings:
    $key_6c90 = { 3f ff [2] 1b f1 [2] 30 dd [2] 1e ff [2] 0a e4 [2] 05 fe [2] 1b e3 [2] 19 e2 [2] 02 e4 [2] 1e e3 [2] 02 cc }

  condition:
    any of them
}