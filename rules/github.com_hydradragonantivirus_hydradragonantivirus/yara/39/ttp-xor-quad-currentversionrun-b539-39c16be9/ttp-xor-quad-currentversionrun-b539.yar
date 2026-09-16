rule TTP_XOR_QUAD_CurrentVersionRun_b539 {
  strings:
    $key_b539 = { e6 56 [2] c2 58 [2] e9 74 [2] c7 56 [2] d3 4d [2] dc 57 [2] c2 4a [2] c0 4b [2] db 4d [2] c7 4a [2] db 65 }

  condition:
    any of them
}