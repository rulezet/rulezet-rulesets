rule TTP_XOR_QUAD_CurrentVersionRun_b6f2 {
  strings:
    $key_b6f2 = { e5 9d [2] c1 93 [2] ea bf [2] c4 9d [2] d0 86 [2] df 9c [2] c1 81 [2] c3 80 [2] d8 86 [2] c4 81 [2] d8 ae }

  condition:
    any of them
}