rule TTP_XOR_QUAD_CurrentVersionRun_b028 {
  strings:
    $key_b028 = { e3 47 [2] c7 49 [2] ec 65 [2] c2 47 [2] d6 5c [2] d9 46 [2] c7 5b [2] c5 5a [2] de 5c [2] c2 5b [2] de 74 }

  condition:
    any of them
}