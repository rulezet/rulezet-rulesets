rule TTP_XOR_QUAD_CurrentVersionRun_b569 {
  strings:
    $key_b569 = { e6 06 [2] c2 08 [2] e9 24 [2] c7 06 [2] d3 1d [2] dc 07 [2] c2 1a [2] c0 1b [2] db 1d [2] c7 1a [2] db 35 }

  condition:
    any of them
}