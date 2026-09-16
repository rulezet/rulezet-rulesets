rule TTP_XOR_QUAD_CurrentVersionRun_b526 {
  strings:
    $key_b526 = { e6 49 [2] c2 47 [2] e9 6b [2] c7 49 [2] d3 52 [2] dc 48 [2] c2 55 [2] c0 54 [2] db 52 [2] c7 55 [2] db 7a }

  condition:
    any of them
}