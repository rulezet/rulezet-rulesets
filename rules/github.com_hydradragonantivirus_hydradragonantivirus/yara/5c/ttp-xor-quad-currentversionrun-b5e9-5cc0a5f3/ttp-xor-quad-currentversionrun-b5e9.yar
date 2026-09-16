rule TTP_XOR_QUAD_CurrentVersionRun_b5e9 {
  strings:
    $key_b5e9 = { e6 86 [2] c2 88 [2] e9 a4 [2] c7 86 [2] d3 9d [2] dc 87 [2] c2 9a [2] c0 9b [2] db 9d [2] c7 9a [2] db b5 }

  condition:
    any of them
}