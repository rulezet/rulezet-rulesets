rule TTP_XOR_QUAD_CurrentVersionRun_6590 {
  strings:
    $key_6590 = { 36 ff [2] 12 f1 [2] 39 dd [2] 17 ff [2] 03 e4 [2] 0c fe [2] 12 e3 [2] 10 e2 [2] 0b e4 [2] 17 e3 [2] 0b cc }

  condition:
    any of them
}