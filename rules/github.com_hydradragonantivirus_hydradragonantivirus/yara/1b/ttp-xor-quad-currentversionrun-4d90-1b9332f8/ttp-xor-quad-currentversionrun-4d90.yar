rule TTP_XOR_QUAD_CurrentVersionRun_4d90 {
  strings:
    $key_4d90 = { 1e ff [2] 3a f1 [2] 11 dd [2] 3f ff [2] 2b e4 [2] 24 fe [2] 3a e3 [2] 38 e2 [2] 23 e4 [2] 3f e3 [2] 23 cc }

  condition:
    any of them
}