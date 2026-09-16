rule TTP_XOR_QUAD_CurrentVersionRun_b06a {
  strings:
    $key_b06a = { e3 05 [2] c7 0b [2] ec 27 [2] c2 05 [2] d6 1e [2] d9 04 [2] c7 19 [2] c5 18 [2] de 1e [2] c2 19 [2] de 36 }

  condition:
    any of them
}