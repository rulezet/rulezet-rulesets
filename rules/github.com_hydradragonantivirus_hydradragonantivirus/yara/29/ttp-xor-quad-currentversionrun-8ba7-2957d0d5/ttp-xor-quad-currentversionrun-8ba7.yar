rule TTP_XOR_QUAD_CurrentVersionRun_8ba7 {
  strings:
    $key_8ba7 = { d8 c8 [2] fc c6 [2] d7 ea [2] f9 c8 [2] ed d3 [2] e2 c9 [2] fc d4 [2] fe d5 [2] e5 d3 [2] f9 d4 [2] e5 fb }

  condition:
    any of them
}