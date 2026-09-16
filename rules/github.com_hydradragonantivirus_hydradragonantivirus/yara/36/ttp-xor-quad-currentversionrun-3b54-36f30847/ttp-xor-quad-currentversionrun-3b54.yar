rule TTP_XOR_QUAD_CurrentVersionRun_3b54 {
  strings:
    $key_3b54 = { 68 3b [2] 4c 35 [2] 67 19 [2] 49 3b [2] 5d 20 [2] 52 3a [2] 4c 27 [2] 4e 26 [2] 55 20 [2] 49 27 [2] 55 08 }

  condition:
    any of them
}