rule TTP_XOR_QUAD_CurrentVersionRun_3d90 {
  strings:
    $key_3d90 = { 6e ff [2] 4a f1 [2] 61 dd [2] 4f ff [2] 5b e4 [2] 54 fe [2] 4a e3 [2] 48 e2 [2] 53 e4 [2] 4f e3 [2] 53 cc }

  condition:
    any of them
}