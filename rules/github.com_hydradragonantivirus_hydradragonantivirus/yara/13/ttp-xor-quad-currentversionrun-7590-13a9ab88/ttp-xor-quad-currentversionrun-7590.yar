rule TTP_XOR_QUAD_CurrentVersionRun_7590 {
  strings:
    $key_7590 = { 26 ff [2] 02 f1 [2] 29 dd [2] 07 ff [2] 13 e4 [2] 1c fe [2] 02 e3 [2] 00 e2 [2] 1b e4 [2] 07 e3 [2] 1b cc }

  condition:
    any of them
}