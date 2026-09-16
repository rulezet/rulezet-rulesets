rule TTP_XOR_QUAD_CurrentVersionRun_b543 {
  strings:
    $key_b543 = { e6 2c [2] c2 22 [2] e9 0e [2] c7 2c [2] d3 37 [2] dc 2d [2] c2 30 [2] c0 31 [2] db 37 [2] c7 30 [2] db 1f }

  condition:
    any of them
}