rule TTP_XOR_QUAD_CurrentVersionRun_23e5 {
  strings:
    $key_23e5 = { 70 8a [2] 54 84 [2] 7f a8 [2] 51 8a [2] 45 91 [2] 4a 8b [2] 54 96 [2] 56 97 [2] 4d 91 [2] 51 96 [2] 4d b9 }

  condition:
    any of them
}