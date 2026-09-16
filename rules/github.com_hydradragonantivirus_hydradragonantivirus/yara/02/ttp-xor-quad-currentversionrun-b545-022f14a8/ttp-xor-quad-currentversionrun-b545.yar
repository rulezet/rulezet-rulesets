rule TTP_XOR_QUAD_CurrentVersionRun_b545 {
  strings:
    $key_b545 = { e6 2a [2] c2 24 [2] e9 08 [2] c7 2a [2] d3 31 [2] dc 2b [2] c2 36 [2] c0 37 [2] db 31 [2] c7 36 [2] db 19 }

  condition:
    any of them
}