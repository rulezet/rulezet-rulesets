rule TTP_XOR_QUAD_CurrentVersionRun_b558 {
  strings:
    $key_b558 = { e6 37 [2] c2 39 [2] e9 15 [2] c7 37 [2] d3 2c [2] dc 36 [2] c2 2b [2] c0 2a [2] db 2c [2] c7 2b [2] db 04 }

  condition:
    any of them
}