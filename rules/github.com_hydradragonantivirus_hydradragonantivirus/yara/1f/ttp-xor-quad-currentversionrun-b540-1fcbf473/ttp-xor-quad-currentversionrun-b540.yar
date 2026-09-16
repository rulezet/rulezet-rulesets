rule TTP_XOR_QUAD_CurrentVersionRun_b540 {
  strings:
    $key_b540 = { e6 2f [2] c2 21 [2] e9 0d [2] c7 2f [2] d3 34 [2] dc 2e [2] c2 33 [2] c0 32 [2] db 34 [2] c7 33 [2] db 1c }

  condition:
    any of them
}