rule TTP_XOR_QUAD_CurrentVersionRun_b52b {
  strings:
    $key_b52b = { e6 44 [2] c2 4a [2] e9 66 [2] c7 44 [2] d3 5f [2] dc 45 [2] c2 58 [2] c0 59 [2] db 5f [2] c7 58 [2] db 77 }

  condition:
    any of them
}