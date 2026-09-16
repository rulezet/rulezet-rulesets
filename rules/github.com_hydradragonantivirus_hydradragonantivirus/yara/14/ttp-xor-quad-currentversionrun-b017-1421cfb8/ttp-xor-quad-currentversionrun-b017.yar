rule TTP_XOR_QUAD_CurrentVersionRun_b017 {
  strings:
    $key_b017 = { e3 78 [2] c7 76 [2] ec 5a [2] c2 78 [2] d6 63 [2] d9 79 [2] c7 64 [2] c5 65 [2] de 63 [2] c2 64 [2] de 4b }

  condition:
    any of them
}