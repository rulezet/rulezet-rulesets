rule TTP_XOR_QUAD_CurrentVersionRun_f1b1 {
  strings:
    $key_f1b1 = { a2 de [2] 86 d0 [2] ad fc [2] 83 de [2] 97 c5 [2] 98 df [2] 86 c2 [2] 84 c3 [2] 9f c5 [2] 83 c2 [2] 9f ed }

  condition:
    any of them
}