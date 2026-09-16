rule TTP_XOR_QUAD_CurrentVersionRun_e6b1 {
  strings:
    $key_e6b1 = { b5 de [2] 91 d0 [2] ba fc [2] 94 de [2] 80 c5 [2] 8f df [2] 91 c2 [2] 93 c3 [2] 88 c5 [2] 94 c2 [2] 88 ed }

  condition:
    any of them
}