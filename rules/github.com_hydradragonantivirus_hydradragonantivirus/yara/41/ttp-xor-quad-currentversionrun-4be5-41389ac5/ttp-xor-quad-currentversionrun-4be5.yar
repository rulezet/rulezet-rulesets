rule TTP_XOR_QUAD_CurrentVersionRun_4be5 {
  strings:
    $key_4be5 = { 18 8a [2] 3c 84 [2] 17 a8 [2] 39 8a [2] 2d 91 [2] 22 8b [2] 3c 96 [2] 3e 97 [2] 25 91 [2] 39 96 [2] 25 b9 }

  condition:
    any of them
}