rule TTP_XOR_QUAD_CurrentVersionRun_b552 {
  strings:
    $key_b552 = { e6 3d [2] c2 33 [2] e9 1f [2] c7 3d [2] d3 26 [2] dc 3c [2] c2 21 [2] c0 20 [2] db 26 [2] c7 21 [2] db 0e }

  condition:
    any of them
}