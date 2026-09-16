rule TTP_XOR_QUAD_CurrentVersionRun_b5ec {
  strings:
    $key_b5ec = { e6 83 [2] c2 8d [2] e9 a1 [2] c7 83 [2] d3 98 [2] dc 82 [2] c2 9f [2] c0 9e [2] db 98 [2] c7 9f [2] db b0 }

  condition:
    any of them
}