rule TTP_XOR_QUAD_CurrentVersionRun_b05e {
  strings:
    $key_b05e = { e3 31 [2] c7 3f [2] ec 13 [2] c2 31 [2] d6 2a [2] d9 30 [2] c7 2d [2] c5 2c [2] de 2a [2] c2 2d [2] de 02 }

  condition:
    any of them
}