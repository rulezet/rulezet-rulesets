rule TTP_XOR_QUAD_CurrentVersionRun_f993 {
  strings:
    $key_f993 = { aa fc [2] 8e f2 [2] a5 de [2] 8b fc [2] 9f e7 [2] 90 fd [2] 8e e0 [2] 8c e1 [2] 97 e7 [2] 8b e0 [2] 97 cf }

  condition:
    any of them
}