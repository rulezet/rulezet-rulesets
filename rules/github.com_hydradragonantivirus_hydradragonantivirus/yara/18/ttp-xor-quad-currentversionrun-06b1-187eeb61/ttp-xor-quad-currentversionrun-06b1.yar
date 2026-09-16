rule TTP_XOR_QUAD_CurrentVersionRun_06b1 {
  strings:
    $key_06b1 = { 55 de [2] 71 d0 [2] 5a fc [2] 74 de [2] 60 c5 [2] 6f df [2] 71 c2 [2] 73 c3 [2] 68 c5 [2] 74 c2 [2] 68 ed }

  condition:
    any of them
}