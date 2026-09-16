rule TTP_XOR_QUAD_CurrentVersionRun_b067 {
  strings:
    $key_b067 = { e3 08 [2] c7 06 [2] ec 2a [2] c2 08 [2] d6 13 [2] d9 09 [2] c7 14 [2] c5 15 [2] de 13 [2] c2 14 [2] de 3b }

  condition:
    any of them
}