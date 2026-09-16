rule TTP_XOR_QUAD_CurrentVersionRun_b019 {
  strings:
    $key_b019 = { e3 76 [2] c7 78 [2] ec 54 [2] c2 76 [2] d6 6d [2] d9 77 [2] c7 6a [2] c5 6b [2] de 6d [2] c2 6a [2] de 45 }

  condition:
    any of them
}