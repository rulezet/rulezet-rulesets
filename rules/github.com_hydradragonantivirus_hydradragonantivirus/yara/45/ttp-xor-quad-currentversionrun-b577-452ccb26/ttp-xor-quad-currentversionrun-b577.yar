rule TTP_XOR_QUAD_CurrentVersionRun_b577 {
  strings:
    $key_b577 = { e6 18 [2] c2 16 [2] e9 3a [2] c7 18 [2] d3 03 [2] dc 19 [2] c2 04 [2] c0 05 [2] db 03 [2] c7 04 [2] db 2b }

  condition:
    any of them
}