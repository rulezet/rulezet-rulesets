rule TTP_XOR_QUAD_CurrentVersionRun_b51a {
  strings:
    $key_b51a = { e6 75 [2] c2 7b [2] e9 57 [2] c7 75 [2] d3 6e [2] dc 74 [2] c2 69 [2] c0 68 [2] db 6e [2] c7 69 [2] db 46 }

  condition:
    any of them
}