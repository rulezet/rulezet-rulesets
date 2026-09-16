rule TTP_XOR_QUAD_CurrentVersionRun_0be5 {
  strings:
    $key_0be5 = { 58 8a [2] 7c 84 [2] 57 a8 [2] 79 8a [2] 6d 91 [2] 62 8b [2] 7c 96 [2] 7e 97 [2] 65 91 [2] 79 96 [2] 65 b9 }

  condition:
    any of them
}