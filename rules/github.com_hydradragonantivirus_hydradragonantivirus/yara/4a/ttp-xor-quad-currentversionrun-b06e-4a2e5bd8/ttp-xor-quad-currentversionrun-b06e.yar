rule TTP_XOR_QUAD_CurrentVersionRun_b06e {
  strings:
    $key_b06e = { e3 01 [2] c7 0f [2] ec 23 [2] c2 01 [2] d6 1a [2] d9 00 [2] c7 1d [2] c5 1c [2] de 1a [2] c2 1d [2] de 32 }

  condition:
    any of them
}