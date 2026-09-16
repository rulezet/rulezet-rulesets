rule TTP_XOR_QUAD_CurrentVersionRun_b549 {
  strings:
    $key_b549 = { e6 26 [2] c2 28 [2] e9 04 [2] c7 26 [2] d3 3d [2] dc 27 [2] c2 3a [2] c0 3b [2] db 3d [2] c7 3a [2] db 15 }

  condition:
    any of them
}