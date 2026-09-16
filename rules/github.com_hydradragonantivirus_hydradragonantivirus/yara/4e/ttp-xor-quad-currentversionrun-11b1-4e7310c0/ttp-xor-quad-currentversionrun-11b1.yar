rule TTP_XOR_QUAD_CurrentVersionRun_11b1 {
  strings:
    $key_11b1 = { 42 de [2] 66 d0 [2] 4d fc [2] 63 de [2] 77 c5 [2] 78 df [2] 66 c2 [2] 64 c3 [2] 7f c5 [2] 63 c2 [2] 7f ed }

  condition:
    any of them
}