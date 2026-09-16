rule TTP_XOR_QUAD_CurrentVersionRun_b5ea {
  strings:
    $key_b5ea = { e6 85 [2] c2 8b [2] e9 a7 [2] c7 85 [2] d3 9e [2] dc 84 [2] c2 99 [2] c0 98 [2] db 9e [2] c7 99 [2] db b6 }

  condition:
    any of them
}