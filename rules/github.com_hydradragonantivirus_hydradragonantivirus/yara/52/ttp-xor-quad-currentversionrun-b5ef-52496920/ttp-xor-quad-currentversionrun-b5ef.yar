rule TTP_XOR_QUAD_CurrentVersionRun_b5ef {
  strings:
    $key_b5ef = { e6 80 [2] c2 8e [2] e9 a2 [2] c7 80 [2] d3 9b [2] dc 81 [2] c2 9c [2] c0 9d [2] db 9b [2] c7 9c [2] db b3 }

  condition:
    any of them
}