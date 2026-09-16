rule TTP_XOR_QUAD_CurrentVersionRun_b5f7 {
  strings:
    $key_b5f7 = { e6 98 [2] c2 96 [2] e9 ba [2] c7 98 [2] d3 83 [2] dc 99 [2] c2 84 [2] c0 85 [2] db 83 [2] c7 84 [2] db ab }

  condition:
    any of them
}