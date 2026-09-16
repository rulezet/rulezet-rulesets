rule TTP_XOR_QUAD_CurrentVersionRun_4bf8 {
  strings:
    $key_4bf8 = { 18 97 [2] 3c 99 [2] 17 b5 [2] 39 97 [2] 2d 8c [2] 22 96 [2] 3c 8b [2] 3e 8a [2] 25 8c [2] 39 8b [2] 25 a4 }

  condition:
    any of them
}