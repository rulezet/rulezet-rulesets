rule TTP_XOR_QUAD_CurrentVersionRun_2ae5 {
  strings:
    $key_2ae5 = { 79 8a [2] 5d 84 [2] 76 a8 [2] 58 8a [2] 4c 91 [2] 43 8b [2] 5d 96 [2] 5f 97 [2] 44 91 [2] 58 96 [2] 44 b9 }

  condition:
    any of them
}