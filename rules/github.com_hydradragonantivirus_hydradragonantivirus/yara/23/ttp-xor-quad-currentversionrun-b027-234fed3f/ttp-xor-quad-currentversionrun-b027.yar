rule TTP_XOR_QUAD_CurrentVersionRun_b027 {
  strings:
    $key_b027 = { e3 48 [2] c7 46 [2] ec 6a [2] c2 48 [2] d6 53 [2] d9 49 [2] c7 54 [2] c5 55 [2] de 53 [2] c2 54 [2] de 7b }

  condition:
    any of them
}