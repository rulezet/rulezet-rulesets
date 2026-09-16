rule TTP_XOR_QUAD_CurrentVersionRun_b0f4 {
  strings:
    $key_b0f4 = { e3 9b [2] c7 95 [2] ec b9 [2] c2 9b [2] d6 80 [2] d9 9a [2] c7 87 [2] c5 86 [2] de 80 [2] c2 87 [2] de a8 }

  condition:
    any of them
}