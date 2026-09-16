rule TTP_XOR_QUAD_CurrentVersionRun_b546 {
  strings:
    $key_b546 = { e6 29 [2] c2 27 [2] e9 0b [2] c7 29 [2] d3 32 [2] dc 28 [2] c2 35 [2] c0 34 [2] db 32 [2] c7 35 [2] db 1a }

  condition:
    any of them
}