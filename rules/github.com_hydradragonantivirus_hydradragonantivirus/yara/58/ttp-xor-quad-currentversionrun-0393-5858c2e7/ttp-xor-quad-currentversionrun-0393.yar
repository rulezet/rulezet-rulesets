rule TTP_XOR_QUAD_CurrentVersionRun_0393 {
  strings:
    $key_0393 = { 50 fc [2] 74 f2 [2] 5f de [2] 71 fc [2] 65 e7 [2] 6a fd [2] 74 e0 [2] 76 e1 [2] 6d e7 [2] 71 e0 [2] 6d cf }

  condition:
    any of them
}