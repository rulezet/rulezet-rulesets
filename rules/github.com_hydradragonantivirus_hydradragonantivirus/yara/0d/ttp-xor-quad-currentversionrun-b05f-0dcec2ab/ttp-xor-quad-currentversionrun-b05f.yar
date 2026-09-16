rule TTP_XOR_QUAD_CurrentVersionRun_b05f {
  strings:
    $key_b05f = { e3 30 [2] c7 3e [2] ec 12 [2] c2 30 [2] d6 2b [2] d9 31 [2] c7 2c [2] c5 2d [2] de 2b [2] c2 2c [2] de 03 }

  condition:
    any of them
}