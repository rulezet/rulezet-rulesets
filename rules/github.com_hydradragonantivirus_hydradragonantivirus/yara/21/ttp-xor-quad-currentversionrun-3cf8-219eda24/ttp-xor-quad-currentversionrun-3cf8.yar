rule TTP_XOR_QUAD_CurrentVersionRun_3cf8 {
  strings:
    $key_3cf8 = { 6f 97 [2] 4b 99 [2] 60 b5 [2] 4e 97 [2] 5a 8c [2] 55 96 [2] 4b 8b [2] 49 8a [2] 52 8c [2] 4e 8b [2] 52 a4 }

  condition:
    any of them
}