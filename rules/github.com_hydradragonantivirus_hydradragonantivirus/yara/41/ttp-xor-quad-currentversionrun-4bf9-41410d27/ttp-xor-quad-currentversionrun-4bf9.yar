rule TTP_XOR_QUAD_CurrentVersionRun_4bf9 {
  strings:
    $key_4bf9 = { 18 96 [2] 3c 98 [2] 17 b4 [2] 39 96 [2] 2d 8d [2] 22 97 [2] 3c 8a [2] 3e 8b [2] 25 8d [2] 39 8a [2] 25 a5 }

  condition:
    any of them
}