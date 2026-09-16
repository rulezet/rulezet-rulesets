rule TTP_XOR_QUAD_CurrentVersionRun_b04e {
  strings:
    $key_b04e = { e3 21 [2] c7 2f [2] ec 03 [2] c2 21 [2] d6 3a [2] d9 20 [2] c7 3d [2] c5 3c [2] de 3a [2] c2 3d [2] de 12 }

  condition:
    any of them
}