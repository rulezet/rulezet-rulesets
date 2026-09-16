rule TTP_XOR_QUAD_CurrentVersionRun_b57d {
  strings:
    $key_b57d = { e6 12 [2] c2 1c [2] e9 30 [2] c7 12 [2] d3 09 [2] dc 13 [2] c2 0e [2] c0 0f [2] db 09 [2] c7 0e [2] db 21 }

  condition:
    any of them
}