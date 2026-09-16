rule TTP_XOR_QUAD_CurrentVersionRun_b54c {
  strings:
    $key_b54c = { e6 23 [2] c2 2d [2] e9 01 [2] c7 23 [2] d3 38 [2] dc 22 [2] c2 3f [2] c0 3e [2] db 38 [2] c7 3f [2] db 10 }

  condition:
    any of them
}