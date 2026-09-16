rule TTP_XOR_QUAD_CurrentVersionRun_26e5 {
  strings:
    $key_26e5 = { 75 8a [2] 51 84 [2] 7a a8 [2] 54 8a [2] 40 91 [2] 4f 8b [2] 51 96 [2] 53 97 [2] 48 91 [2] 54 96 [2] 48 b9 }

  condition:
    any of them
}