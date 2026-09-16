rule TTP_XOR_QUAD_CurrentVersionRun_b509 {
  strings:
    $key_b509 = { e6 66 [2] c2 68 [2] e9 44 [2] c7 66 [2] d3 7d [2] dc 67 [2] c2 7a [2] c0 7b [2] db 7d [2] c7 7a [2] db 55 }

  condition:
    any of them
}