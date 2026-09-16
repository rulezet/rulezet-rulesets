rule TTP_XOR_QUAD_CurrentVersionRun_b03e {
  strings:
    $key_b03e = { e3 51 [2] c7 5f [2] ec 73 [2] c2 51 [2] d6 4a [2] d9 50 [2] c7 4d [2] c5 4c [2] de 4a [2] c2 4d [2] de 62 }

  condition:
    any of them
}