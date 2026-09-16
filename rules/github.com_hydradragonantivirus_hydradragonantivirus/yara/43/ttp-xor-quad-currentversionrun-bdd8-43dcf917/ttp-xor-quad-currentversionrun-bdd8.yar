rule TTP_XOR_QUAD_CurrentVersionRun_bdd8 {
  strings:
    $key_bdd8 = { ee b7 [2] ca b9 [2] e1 95 [2] cf b7 [2] db ac [2] d4 b6 [2] ca ab [2] c8 aa [2] d3 ac [2] cf ab [2] d3 84 }

  condition:
    any of them
}