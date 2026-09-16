rule TTP_XOR_QUAD_CurrentVersionRun_b570 {
  strings:
    $key_b570 = { e6 1f [2] c2 11 [2] e9 3d [2] c7 1f [2] d3 04 [2] dc 1e [2] c2 03 [2] c0 02 [2] db 04 [2] c7 03 [2] db 2c }

  condition:
    any of them
}