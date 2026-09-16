rule TTP_XOR_QUAD_CurrentVersionRun_b04c {
  strings:
    $key_b04c = { e3 23 [2] c7 2d [2] ec 01 [2] c2 23 [2] d6 38 [2] d9 22 [2] c7 3f [2] c5 3e [2] de 38 [2] c2 3f [2] de 10 }

  condition:
    any of them
}