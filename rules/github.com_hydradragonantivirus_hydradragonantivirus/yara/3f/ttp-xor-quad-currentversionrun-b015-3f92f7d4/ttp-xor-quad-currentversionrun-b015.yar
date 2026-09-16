rule TTP_XOR_QUAD_CurrentVersionRun_b015 {
  strings:
    $key_b015 = { e3 7a [2] c7 74 [2] ec 58 [2] c2 7a [2] d6 61 [2] d9 7b [2] c7 66 [2] c5 67 [2] de 61 [2] c2 66 [2] de 49 }

  condition:
    any of them
}