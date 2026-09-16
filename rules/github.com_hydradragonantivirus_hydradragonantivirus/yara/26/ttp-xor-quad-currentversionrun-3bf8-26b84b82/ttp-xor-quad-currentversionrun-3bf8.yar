rule TTP_XOR_QUAD_CurrentVersionRun_3bf8 {
  strings:
    $key_3bf8 = { 68 97 [2] 4c 99 [2] 67 b5 [2] 49 97 [2] 5d 8c [2] 52 96 [2] 4c 8b [2] 4e 8a [2] 55 8c [2] 49 8b [2] 55 a4 }

  condition:
    any of them
}