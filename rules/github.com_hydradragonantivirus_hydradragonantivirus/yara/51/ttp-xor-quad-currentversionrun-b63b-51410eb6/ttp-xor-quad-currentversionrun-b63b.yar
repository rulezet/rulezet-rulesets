rule TTP_XOR_QUAD_CurrentVersionRun_b63b {
  strings:
    $key_b63b = { e5 54 [2] c1 5a [2] ea 76 [2] c4 54 [2] d0 4f [2] df 55 [2] c1 48 [2] c3 49 [2] d8 4f [2] c4 48 [2] d8 67 }

  condition:
    any of them
}