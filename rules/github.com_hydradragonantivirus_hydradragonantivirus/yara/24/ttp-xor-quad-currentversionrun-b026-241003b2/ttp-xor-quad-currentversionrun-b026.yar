rule TTP_XOR_QUAD_CurrentVersionRun_b026 {
  strings:
    $key_b026 = { e3 49 [2] c7 47 [2] ec 6b [2] c2 49 [2] d6 52 [2] d9 48 [2] c7 55 [2] c5 54 [2] de 52 [2] c2 55 [2] de 7a }

  condition:
    any of them
}