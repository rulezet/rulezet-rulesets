rule TTP_XOR_QUAD_CurrentVersionRun_3b44 {
  strings:
    $key_3b44 = { 68 2b [2] 4c 25 [2] 67 09 [2] 49 2b [2] 5d 30 [2] 52 2a [2] 4c 37 [2] 4e 36 [2] 55 30 [2] 49 37 [2] 55 18 }

  condition:
    any of them
}