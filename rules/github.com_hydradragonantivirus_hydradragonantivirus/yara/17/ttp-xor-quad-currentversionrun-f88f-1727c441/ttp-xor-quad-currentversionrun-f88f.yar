rule TTP_XOR_QUAD_CurrentVersionRun_f88f {
  strings:
    $key_f88f = { ab e0 [2] 8f ee [2] a4 c2 [2] 8a e0 [2] 9e fb [2] 91 e1 [2] 8f fc [2] 8d fd [2] 96 fb [2] 8a fc [2] 96 d3 }

  condition:
    any of them
}