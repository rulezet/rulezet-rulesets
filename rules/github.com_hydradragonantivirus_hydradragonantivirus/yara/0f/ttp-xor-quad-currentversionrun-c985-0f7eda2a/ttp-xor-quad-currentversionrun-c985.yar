rule TTP_XOR_QUAD_CurrentVersionRun_c985 {
  strings:
    $key_c985 = { 9a ea [2] be e4 [2] 95 c8 [2] bb ea [2] af f1 [2] a0 eb [2] be f6 [2] bc f7 [2] a7 f1 [2] bb f6 [2] a7 d9 }

  condition:
    any of them
}