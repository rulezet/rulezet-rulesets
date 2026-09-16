rule TTP_XOR_QUAD_CurrentVersionRun_5093 {
  strings:
    $key_5093 = { 03 fc [2] 27 f2 [2] 0c de [2] 22 fc [2] 36 e7 [2] 39 fd [2] 27 e0 [2] 25 e1 [2] 3e e7 [2] 22 e0 [2] 3e cf }

  condition:
    any of them
}