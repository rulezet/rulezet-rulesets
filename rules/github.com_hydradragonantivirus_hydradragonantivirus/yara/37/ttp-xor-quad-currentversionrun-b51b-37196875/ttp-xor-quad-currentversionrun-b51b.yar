rule TTP_XOR_QUAD_CurrentVersionRun_b51b {
  strings:
    $key_b51b = { e6 74 [2] c2 7a [2] e9 56 [2] c7 74 [2] d3 6f [2] dc 75 [2] c2 68 [2] c0 69 [2] db 6f [2] c7 68 [2] db 47 }

  condition:
    any of them
}