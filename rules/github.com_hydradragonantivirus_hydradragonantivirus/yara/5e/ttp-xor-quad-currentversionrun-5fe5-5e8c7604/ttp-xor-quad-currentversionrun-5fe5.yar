rule TTP_XOR_QUAD_CurrentVersionRun_5fe5 {
  strings:
    $key_5fe5 = { 0c 8a [2] 28 84 [2] 03 a8 [2] 2d 8a [2] 39 91 [2] 36 8b [2] 28 96 [2] 2a 97 [2] 31 91 [2] 2d 96 [2] 31 b9 }

  condition:
    any of them
}