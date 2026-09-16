rule TTP_XOR_QUAD_CurrentVersionRun_388f {
  strings:
    $key_388f = { 6b e0 [2] 4f ee [2] 64 c2 [2] 4a e0 [2] 5e fb [2] 51 e1 [2] 4f fc [2] 4d fd [2] 56 fb [2] 4a fc [2] 56 d3 }

  condition:
    any of them
}