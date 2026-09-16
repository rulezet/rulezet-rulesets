rule TTP_XOR_QUAD_CurrentVersionRun_64e5 {
  strings:
    $key_64e5 = { 37 8a [2] 13 84 [2] 38 a8 [2] 16 8a [2] 02 91 [2] 0d 8b [2] 13 96 [2] 11 97 [2] 0a 91 [2] 16 96 [2] 0a b9 }

  condition:
    any of them
}