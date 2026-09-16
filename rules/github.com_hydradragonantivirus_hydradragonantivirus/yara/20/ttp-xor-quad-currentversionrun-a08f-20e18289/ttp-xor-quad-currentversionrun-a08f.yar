rule TTP_XOR_QUAD_CurrentVersionRun_a08f {
  strings:
    $key_a08f = { f3 e0 [2] d7 ee [2] fc c2 [2] d2 e0 [2] c6 fb [2] c9 e1 [2] d7 fc [2] d5 fd [2] ce fb [2] d2 fc [2] ce d3 }

  condition:
    any of them
}