rule TTP_XOR_QUAD_CurrentVersionRun_4393 {
  strings:
    $key_4393 = { 10 fc [2] 34 f2 [2] 1f de [2] 31 fc [2] 25 e7 [2] 2a fd [2] 34 e0 [2] 36 e1 [2] 2d e7 [2] 31 e0 [2] 2d cf }

  condition:
    any of them
}