rule TTP_XOR_QUAD_CurrentVersionRun_b535 {
  strings:
    $key_b535 = { e6 5a [2] c2 54 [2] e9 78 [2] c7 5a [2] d3 41 [2] dc 5b [2] c2 46 [2] c0 47 [2] db 41 [2] c7 46 [2] db 69 }

  condition:
    any of them
}