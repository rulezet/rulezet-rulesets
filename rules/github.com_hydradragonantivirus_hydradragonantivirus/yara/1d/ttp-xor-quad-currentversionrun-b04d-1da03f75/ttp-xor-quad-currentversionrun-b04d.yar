rule TTP_XOR_QUAD_CurrentVersionRun_b04d {
  strings:
    $key_b04d = { e3 22 [2] c7 2c [2] ec 00 [2] c2 22 [2] d6 39 [2] d9 23 [2] c7 3e [2] c5 3f [2] de 39 [2] c2 3e [2] de 11 }

  condition:
    any of them
}