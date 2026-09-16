rule TTP_XOR_QUAD_CurrentVersionRun_588f {
  strings:
    $key_588f = { 0b e0 [2] 2f ee [2] 04 c2 [2] 2a e0 [2] 3e fb [2] 31 e1 [2] 2f fc [2] 2d fd [2] 36 fb [2] 2a fc [2] 36 d3 }

  condition:
    any of them
}