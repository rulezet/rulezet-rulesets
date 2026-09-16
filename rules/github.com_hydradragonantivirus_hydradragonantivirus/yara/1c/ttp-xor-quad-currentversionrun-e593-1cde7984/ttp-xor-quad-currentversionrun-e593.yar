rule TTP_XOR_QUAD_CurrentVersionRun_e593 {
  strings:
    $key_e593 = { b6 fc [2] 92 f2 [2] b9 de [2] 97 fc [2] 83 e7 [2] 8c fd [2] 92 e0 [2] 90 e1 [2] 8b e7 [2] 97 e0 [2] 8b cf }

  condition:
    any of them
}