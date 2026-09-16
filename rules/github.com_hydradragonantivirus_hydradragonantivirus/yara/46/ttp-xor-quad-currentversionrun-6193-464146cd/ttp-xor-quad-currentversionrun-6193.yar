rule TTP_XOR_QUAD_CurrentVersionRun_6193 {
  strings:
    $key_6193 = { 32 fc [2] 16 f2 [2] 3d de [2] 13 fc [2] 07 e7 [2] 08 fd [2] 16 e0 [2] 14 e1 [2] 0f e7 [2] 13 e0 [2] 0f cf }

  condition:
    any of them
}