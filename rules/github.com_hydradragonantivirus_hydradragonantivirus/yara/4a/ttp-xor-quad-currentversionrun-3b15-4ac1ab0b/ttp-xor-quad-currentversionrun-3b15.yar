rule TTP_XOR_QUAD_CurrentVersionRun_3b15 {
  strings:
    $key_3b15 = { 68 7a [2] 4c 74 [2] 67 58 [2] 49 7a [2] 5d 61 [2] 52 7b [2] 4c 66 [2] 4e 67 [2] 55 61 [2] 49 66 [2] 55 49 }

  condition:
    any of them
}