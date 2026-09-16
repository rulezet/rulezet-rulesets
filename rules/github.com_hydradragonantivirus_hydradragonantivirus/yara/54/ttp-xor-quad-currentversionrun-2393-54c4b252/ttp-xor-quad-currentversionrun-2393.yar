rule TTP_XOR_QUAD_CurrentVersionRun_2393 {
  strings:
    $key_2393 = { 70 fc [2] 54 f2 [2] 7f de [2] 51 fc [2] 45 e7 [2] 4a fd [2] 54 e0 [2] 56 e1 [2] 4d e7 [2] 51 e0 [2] 4d cf }

  condition:
    any of them
}