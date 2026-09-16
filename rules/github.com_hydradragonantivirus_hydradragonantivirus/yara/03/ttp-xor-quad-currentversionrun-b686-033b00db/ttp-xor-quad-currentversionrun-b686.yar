rule TTP_XOR_QUAD_CurrentVersionRun_b686 {
  strings:
    $key_b686 = { e5 e9 [2] c1 e7 [2] ea cb [2] c4 e9 [2] d0 f2 [2] df e8 [2] c1 f5 [2] c3 f4 [2] d8 f2 [2] c4 f5 [2] d8 da }

  condition:
    any of them
}