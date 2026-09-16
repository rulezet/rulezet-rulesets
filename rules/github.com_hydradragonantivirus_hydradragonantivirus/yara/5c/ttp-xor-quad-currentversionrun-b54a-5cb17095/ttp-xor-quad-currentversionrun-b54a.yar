rule TTP_XOR_QUAD_CurrentVersionRun_b54a {
  strings:
    $key_b54a = { e6 25 [2] c2 2b [2] e9 07 [2] c7 25 [2] d3 3e [2] dc 24 [2] c2 39 [2] c0 38 [2] db 3e [2] c7 39 [2] db 16 }

  condition:
    any of them
}