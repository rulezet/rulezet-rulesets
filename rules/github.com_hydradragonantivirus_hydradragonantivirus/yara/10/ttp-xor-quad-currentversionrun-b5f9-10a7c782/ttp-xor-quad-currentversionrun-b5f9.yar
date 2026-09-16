rule TTP_XOR_QUAD_CurrentVersionRun_b5f9 {
  strings:
    $key_b5f9 = { e6 96 [2] c2 98 [2] e9 b4 [2] c7 96 [2] d3 8d [2] dc 97 [2] c2 8a [2] c0 8b [2] db 8d [2] c7 8a [2] db a5 }

  condition:
    any of them
}