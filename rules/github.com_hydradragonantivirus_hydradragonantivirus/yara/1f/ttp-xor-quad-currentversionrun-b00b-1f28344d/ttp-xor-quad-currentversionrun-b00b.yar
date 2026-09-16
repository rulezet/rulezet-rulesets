rule TTP_XOR_QUAD_CurrentVersionRun_b00b {
  strings:
    $key_b00b = { e3 64 [2] c7 6a [2] ec 46 [2] c2 64 [2] d6 7f [2] d9 65 [2] c7 78 [2] c5 79 [2] de 7f [2] c2 78 [2] de 57 }

  condition:
    any of them
}