rule TTP_XOR_QUAD_CurrentVersionRun_b568 {
  strings:
    $key_b568 = { e6 07 [2] c2 09 [2] e9 25 [2] c7 07 [2] d3 1c [2] dc 06 [2] c2 1b [2] c0 1a [2] db 1c [2] c7 1b [2] db 34 }

  condition:
    any of them
}