rule TTP_XOR_QUAD_CurrentVersionRun_08e5 {
  strings:
    $key_08e5 = { 5b 8a [2] 7f 84 [2] 54 a8 [2] 7a 8a [2] 6e 91 [2] 61 8b [2] 7f 96 [2] 7d 97 [2] 66 91 [2] 7a 96 [2] 66 b9 }

  condition:
    any of them
}