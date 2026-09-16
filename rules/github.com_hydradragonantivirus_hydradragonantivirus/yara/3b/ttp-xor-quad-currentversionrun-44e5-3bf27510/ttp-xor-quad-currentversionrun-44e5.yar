rule TTP_XOR_QUAD_CurrentVersionRun_44e5 {
  strings:
    $key_44e5 = { 17 8a [2] 33 84 [2] 18 a8 [2] 36 8a [2] 22 91 [2] 2d 8b [2] 33 96 [2] 31 97 [2] 2a 91 [2] 36 96 [2] 2a b9 }

  condition:
    any of them
}