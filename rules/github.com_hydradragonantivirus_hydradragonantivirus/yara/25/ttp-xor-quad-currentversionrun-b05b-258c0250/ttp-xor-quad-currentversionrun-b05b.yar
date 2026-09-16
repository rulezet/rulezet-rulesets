rule TTP_XOR_QUAD_CurrentVersionRun_b05b {
  strings:
    $key_b05b = { e3 34 [2] c7 3a [2] ec 16 [2] c2 34 [2] d6 2f [2] d9 35 [2] c7 28 [2] c5 29 [2] de 2f [2] c2 28 [2] de 07 }

  condition:
    any of them
}