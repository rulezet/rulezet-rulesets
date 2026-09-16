rule TTP_XOR_QUAD_CurrentVersionRun_088f {
  strings:
    $key_088f = { 5b e0 [2] 7f ee [2] 54 c2 [2] 7a e0 [2] 6e fb [2] 61 e1 [2] 7f fc [2] 7d fd [2] 66 fb [2] 7a fc [2] 66 d3 }

  condition:
    any of them
}