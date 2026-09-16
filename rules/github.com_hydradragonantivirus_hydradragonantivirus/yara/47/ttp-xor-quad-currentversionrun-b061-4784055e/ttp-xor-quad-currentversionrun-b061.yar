rule TTP_XOR_QUAD_CurrentVersionRun_b061 {
  strings:
    $key_b061 = { e3 0e [2] c7 00 [2] ec 2c [2] c2 0e [2] d6 15 [2] d9 0f [2] c7 12 [2] c5 13 [2] de 15 [2] c2 12 [2] de 3d }

  condition:
    any of them
}