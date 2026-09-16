rule TTP_XOR_QUAD_CurrentVersionRun_b00e {
  strings:
    $key_b00e = { e3 61 [2] c7 6f [2] ec 43 [2] c2 61 [2] d6 7a [2] d9 60 [2] c7 7d [2] c5 7c [2] de 7a [2] c2 7d [2] de 52 }

  condition:
    any of them
}