rule TTP_XOR_QUAD_CurrentVersionRun_b57a {
  strings:
    $key_b57a = { e6 15 [2] c2 1b [2] e9 37 [2] c7 15 [2] d3 0e [2] dc 14 [2] c2 09 [2] c0 08 [2] db 0e [2] c7 09 [2] db 26 }

  condition:
    any of them
}