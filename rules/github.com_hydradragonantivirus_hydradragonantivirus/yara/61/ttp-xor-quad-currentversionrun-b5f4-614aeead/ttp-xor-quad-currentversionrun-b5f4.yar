rule TTP_XOR_QUAD_CurrentVersionRun_b5f4 {
  strings:
    $key_b5f4 = { e6 9b [2] c2 95 [2] e9 b9 [2] c7 9b [2] d3 80 [2] dc 9a [2] c2 87 [2] c0 86 [2] db 80 [2] c7 87 [2] db a8 }

  condition:
    any of them
}