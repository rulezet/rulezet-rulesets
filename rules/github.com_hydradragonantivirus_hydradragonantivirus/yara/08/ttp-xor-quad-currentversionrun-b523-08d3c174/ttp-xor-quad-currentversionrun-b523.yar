rule TTP_XOR_QUAD_CurrentVersionRun_b523 {
  strings:
    $key_b523 = { e6 4c [2] c2 42 [2] e9 6e [2] c7 4c [2] d3 57 [2] dc 4d [2] c2 50 [2] c0 51 [2] db 57 [2] c7 50 [2] db 7f }

  condition:
    any of them
}