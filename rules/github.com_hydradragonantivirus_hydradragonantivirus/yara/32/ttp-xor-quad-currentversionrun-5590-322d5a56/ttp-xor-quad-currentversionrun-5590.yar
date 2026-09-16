rule TTP_XOR_QUAD_CurrentVersionRun_5590 {
  strings:
    $key_5590 = { 06 ff [2] 22 f1 [2] 09 dd [2] 27 ff [2] 33 e4 [2] 3c fe [2] 22 e3 [2] 20 e2 [2] 3b e4 [2] 27 e3 [2] 3b cc }

  condition:
    any of them
}