rule TTP_XOR_QUAD_CurrentVersionRun_5393 {
  strings:
    $key_5393 = { 00 fc [2] 24 f2 [2] 0f de [2] 21 fc [2] 35 e7 [2] 3a fd [2] 24 e0 [2] 26 e1 [2] 3d e7 [2] 21 e0 [2] 3d cf }

  condition:
    any of them
}