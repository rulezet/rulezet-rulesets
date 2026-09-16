rule TTP_XOR_QUAD_CurrentVersionRun_b559 {
  strings:
    $key_b559 = { e6 36 [2] c2 38 [2] e9 14 [2] c7 36 [2] d3 2d [2] dc 37 [2] c2 2a [2] c0 2b [2] db 2d [2] c7 2a [2] db 05 }

  condition:
    any of them
}