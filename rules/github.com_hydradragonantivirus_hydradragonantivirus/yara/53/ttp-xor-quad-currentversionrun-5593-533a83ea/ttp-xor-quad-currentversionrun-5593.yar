rule TTP_XOR_QUAD_CurrentVersionRun_5593 {
  strings:
    $key_5593 = { 06 fc [2] 22 f2 [2] 09 de [2] 27 fc [2] 33 e7 [2] 3c fd [2] 22 e0 [2] 20 e1 [2] 3b e7 [2] 27 e0 [2] 3b cf }

  condition:
    any of them
}