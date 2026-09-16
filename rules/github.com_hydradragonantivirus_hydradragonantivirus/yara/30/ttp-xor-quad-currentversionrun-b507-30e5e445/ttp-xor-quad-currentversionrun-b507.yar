rule TTP_XOR_QUAD_CurrentVersionRun_b507 {
  strings:
    $key_b507 = { e6 68 [2] c2 66 [2] e9 4a [2] c7 68 [2] d3 73 [2] dc 69 [2] c2 74 [2] c0 75 [2] db 73 [2] c7 74 [2] db 5b }

  condition:
    any of them
}