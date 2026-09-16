rule TTP_XOR_QUAD_CurrentVersionRun_a01b {
  strings:
    $key_a01b = { f3 74 [2] d7 7a [2] fc 56 [2] d2 74 [2] c6 6f [2] c9 75 [2] d7 68 [2] d5 69 [2] ce 6f [2] d2 68 [2] ce 47 }

  condition:
    any of them
}