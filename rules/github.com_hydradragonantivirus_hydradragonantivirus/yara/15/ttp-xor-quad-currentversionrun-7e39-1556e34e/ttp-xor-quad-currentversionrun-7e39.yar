rule TTP_XOR_QUAD_CurrentVersionRun_7e39 {
  strings:
    $key_7e39 = { 2d 56 [2] 09 58 [2] 22 74 [2] 0c 56 [2] 18 4d [2] 17 57 [2] 09 4a [2] 0b 4b [2] 10 4d [2] 0c 4a [2] 10 65 }

  condition:
    any of them
}