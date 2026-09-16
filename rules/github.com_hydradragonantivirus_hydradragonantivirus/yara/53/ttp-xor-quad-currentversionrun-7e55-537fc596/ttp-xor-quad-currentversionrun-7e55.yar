rule TTP_XOR_QUAD_CurrentVersionRun_7e55 {
  strings:
    $key_7e55 = { 2d 3a [2] 09 34 [2] 22 18 [2] 0c 3a [2] 18 21 [2] 17 3b [2] 09 26 [2] 0b 27 [2] 10 21 [2] 0c 26 [2] 10 09 }

  condition:
    any of them
}