rule TTP_XOR_QUAD_CurrentVersionRun_308f {
  strings:
    $key_308f = { 63 e0 [2] 47 ee [2] 6c c2 [2] 42 e0 [2] 56 fb [2] 59 e1 [2] 47 fc [2] 45 fd [2] 5e fb [2] 42 fc [2] 5e d3 }

  condition:
    any of them
}