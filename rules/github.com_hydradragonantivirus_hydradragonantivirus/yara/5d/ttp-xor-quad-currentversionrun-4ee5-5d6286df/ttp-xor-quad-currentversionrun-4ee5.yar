rule TTP_XOR_QUAD_CurrentVersionRun_4ee5 {
  strings:
    $key_4ee5 = { 1d 8a [2] 39 84 [2] 12 a8 [2] 3c 8a [2] 28 91 [2] 27 8b [2] 39 96 [2] 3b 97 [2] 20 91 [2] 3c 96 [2] 20 b9 }

  condition:
    any of them
}