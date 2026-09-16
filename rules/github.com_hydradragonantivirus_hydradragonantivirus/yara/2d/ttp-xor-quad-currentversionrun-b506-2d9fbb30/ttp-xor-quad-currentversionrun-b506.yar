rule TTP_XOR_QUAD_CurrentVersionRun_b506 {
  strings:
    $key_b506 = { e6 69 [2] c2 67 [2] e9 4b [2] c7 69 [2] d3 72 [2] dc 68 [2] c2 75 [2] c0 74 [2] db 72 [2] c7 75 [2] db 5a }

  condition:
    any of them
}