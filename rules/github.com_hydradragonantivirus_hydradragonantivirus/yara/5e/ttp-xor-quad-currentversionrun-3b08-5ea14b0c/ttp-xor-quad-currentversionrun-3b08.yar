rule TTP_XOR_QUAD_CurrentVersionRun_3b08 {
  strings:
    $key_3b08 = { 68 67 [2] 4c 69 [2] 67 45 [2] 49 67 [2] 5d 7c [2] 52 66 [2] 4c 7b [2] 4e 7a [2] 55 7c [2] 49 7b [2] 55 54 }

  condition:
    any of them
}