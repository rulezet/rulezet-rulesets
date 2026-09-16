rule TTP_XOR_QUAD_CurrentVersionRun_b03b {
  strings:
    $key_b03b = { e3 54 [2] c7 5a [2] ec 76 [2] c2 54 [2] d6 4f [2] d9 55 [2] c7 48 [2] c5 49 [2] de 4f [2] c2 48 [2] de 67 }

  condition:
    any of them
}