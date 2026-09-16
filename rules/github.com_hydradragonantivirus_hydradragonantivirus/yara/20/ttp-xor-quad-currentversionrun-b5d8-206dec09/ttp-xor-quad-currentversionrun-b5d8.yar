rule TTP_XOR_QUAD_CurrentVersionRun_b5d8 {
  strings:
    $key_b5d8 = { e6 b7 [2] c2 b9 [2] e9 95 [2] c7 b7 [2] d3 ac [2] dc b6 [2] c2 ab [2] c0 aa [2] db ac [2] c7 ab [2] db 84 }

  condition:
    any of them
}