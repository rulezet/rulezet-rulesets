rule TTP_XOR_QUAD_CurrentVersionRun_4be9 {
  strings:
    $key_4be9 = { 18 86 [2] 3c 88 [2] 17 a4 [2] 39 86 [2] 2d 9d [2] 22 87 [2] 3c 9a [2] 3e 9b [2] 25 9d [2] 39 9a [2] 25 b5 }

  condition:
    any of them
}