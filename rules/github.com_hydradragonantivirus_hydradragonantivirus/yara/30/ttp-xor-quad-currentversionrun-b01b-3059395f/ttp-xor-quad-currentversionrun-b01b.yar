rule TTP_XOR_QUAD_CurrentVersionRun_b01b {
  strings:
    $key_b01b = { e3 74 [2] c7 7a [2] ec 56 [2] c2 74 [2] d6 6f [2] d9 75 [2] c7 68 [2] c5 69 [2] de 6f [2] c2 68 [2] de 47 }

  condition:
    any of them
}