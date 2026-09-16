rule TTP_XOR_QUAD_CurrentVersionRun_2ff8 {
  strings:
    $key_2ff8 = { 7c 97 [2] 58 99 [2] 73 b5 [2] 5d 97 [2] 49 8c [2] 46 96 [2] 58 8b [2] 5a 8a [2] 41 8c [2] 5d 8b [2] 41 a4 }

  condition:
    any of them
}