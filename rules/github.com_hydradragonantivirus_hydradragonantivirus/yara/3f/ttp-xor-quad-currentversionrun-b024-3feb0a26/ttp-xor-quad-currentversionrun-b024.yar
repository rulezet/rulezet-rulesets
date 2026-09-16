rule TTP_XOR_QUAD_CurrentVersionRun_b024 {
  strings:
    $key_b024 = { e3 4b [2] c7 45 [2] ec 69 [2] c2 4b [2] d6 50 [2] d9 4a [2] c7 57 [2] c5 56 [2] de 50 [2] c2 57 [2] de 78 }

  condition:
    any of them
}