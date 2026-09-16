rule TTP_XOR_QUAD_CurrentVersionRun_b579 {
  strings:
    $key_b579 = { e6 16 [2] c2 18 [2] e9 34 [2] c7 16 [2] d3 0d [2] dc 17 [2] c2 0a [2] c0 0b [2] db 0d [2] c7 0a [2] db 25 }

  condition:
    any of them
}