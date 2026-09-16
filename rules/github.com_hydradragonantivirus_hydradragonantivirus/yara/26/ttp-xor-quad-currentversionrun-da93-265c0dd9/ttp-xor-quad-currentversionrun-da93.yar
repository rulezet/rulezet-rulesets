rule TTP_XOR_QUAD_CurrentVersionRun_da93 {
  strings:
    $key_da93 = { 89 fc [2] ad f2 [2] 86 de [2] a8 fc [2] bc e7 [2] b3 fd [2] ad e0 [2] af e1 [2] b4 e7 [2] a8 e0 [2] b4 cf }

  condition:
    any of them
}