rule TTP_XOR_QUAD_CurrentVersionRun_b06c {
  strings:
    $key_b06c = { e3 03 [2] c7 0d [2] ec 21 [2] c2 03 [2] d6 18 [2] d9 02 [2] c7 1f [2] c5 1e [2] de 18 [2] c2 1f [2] de 30 }

  condition:
    any of them
}