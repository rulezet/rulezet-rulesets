rule TTP_XOR_QUAD_CurrentVersionRun_b510 {
  strings:
    $key_b510 = { e6 7f [2] c2 71 [2] e9 5d [2] c7 7f [2] d3 64 [2] dc 7e [2] c2 63 [2] c0 62 [2] db 64 [2] c7 63 [2] db 4c }

  condition:
    any of them
}