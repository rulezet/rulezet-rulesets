rule TTP_XOR_QUAD_CurrentVersionRun_b02e {
  strings:
    $key_b02e = { e3 41 [2] c7 4f [2] ec 63 [2] c2 41 [2] d6 5a [2] d9 40 [2] c7 5d [2] c5 5c [2] de 5a [2] c2 5d [2] de 72 }

  condition:
    any of them
}