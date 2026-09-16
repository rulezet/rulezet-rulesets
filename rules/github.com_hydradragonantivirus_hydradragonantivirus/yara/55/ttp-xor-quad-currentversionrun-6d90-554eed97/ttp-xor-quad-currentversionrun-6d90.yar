rule TTP_XOR_QUAD_CurrentVersionRun_6d90 {
  strings:
    $key_6d90 = { 3e ff [2] 1a f1 [2] 31 dd [2] 1f ff [2] 0b e4 [2] 04 fe [2] 1a e3 [2] 18 e2 [2] 03 e4 [2] 1f e3 [2] 03 cc }

  condition:
    any of them
}