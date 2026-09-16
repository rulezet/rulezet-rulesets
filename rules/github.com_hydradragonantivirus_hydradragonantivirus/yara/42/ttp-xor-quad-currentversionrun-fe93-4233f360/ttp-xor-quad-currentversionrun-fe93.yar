rule TTP_XOR_QUAD_CurrentVersionRun_fe93 {
  strings:
    $key_fe93 = { ad fc [2] 89 f2 [2] a2 de [2] 8c fc [2] 98 e7 [2] 97 fd [2] 89 e0 [2] 8b e1 [2] 90 e7 [2] 8c e0 [2] 90 cf }

  condition:
    any of them
}