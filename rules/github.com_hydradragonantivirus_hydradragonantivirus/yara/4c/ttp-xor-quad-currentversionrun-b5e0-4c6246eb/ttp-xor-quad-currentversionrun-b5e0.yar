rule TTP_XOR_QUAD_CurrentVersionRun_b5e0 {
  strings:
    $key_b5e0 = { e6 8f [2] c2 81 [2] e9 ad [2] c7 8f [2] d3 94 [2] dc 8e [2] c2 93 [2] c0 92 [2] db 94 [2] c7 93 [2] db bc }

  condition:
    any of them
}