rule TTP_XOR_QUAD_CurrentVersionRun_b5e5 {
  strings:
    $key_b5e5 = { e6 8a [2] c2 84 [2] e9 a8 [2] c7 8a [2] d3 91 [2] dc 8b [2] c2 96 [2] c0 97 [2] db 91 [2] c7 96 [2] db b9 }

  condition:
    any of them
}