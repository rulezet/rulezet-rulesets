rule TTP_XOR_QUAD_CurrentVersionRun_b02b {
  strings:
    $key_b02b = { e3 44 [2] c7 4a [2] ec 66 [2] c2 44 [2] d6 5f [2] d9 45 [2] c7 58 [2] c5 59 [2] de 5f [2] c2 58 [2] de 77 }

  condition:
    any of them
}