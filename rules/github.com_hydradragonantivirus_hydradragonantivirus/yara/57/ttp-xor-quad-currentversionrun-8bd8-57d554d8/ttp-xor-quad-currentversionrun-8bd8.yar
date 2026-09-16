rule TTP_XOR_QUAD_CurrentVersionRun_8bd8 {
  strings:
    $key_8bd8 = { d8 b7 [2] fc b9 [2] d7 95 [2] f9 b7 [2] ed ac [2] e2 b6 [2] fc ab [2] fe aa [2] e5 ac [2] f9 ab [2] e5 84 }

  condition:
    any of them
}