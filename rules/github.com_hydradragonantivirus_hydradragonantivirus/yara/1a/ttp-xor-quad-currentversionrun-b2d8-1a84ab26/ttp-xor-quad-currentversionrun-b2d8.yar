rule TTP_XOR_QUAD_CurrentVersionRun_b2d8 {
  strings:
    $key_b2d8 = { e1 b7 [2] c5 b9 [2] ee 95 [2] c0 b7 [2] d4 ac [2] db b6 [2] c5 ab [2] c7 aa [2] dc ac [2] c0 ab [2] dc 84 }

  condition:
    any of them
}