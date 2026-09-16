rule TTP_XOR_QUAD_CurrentVersionRun_b504 {
  strings:
    $key_b504 = { e6 6b [2] c2 65 [2] e9 49 [2] c7 6b [2] d3 70 [2] dc 6a [2] c2 77 [2] c0 76 [2] db 70 [2] c7 77 [2] db 58 }

  condition:
    any of them
}