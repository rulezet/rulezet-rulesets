rule TTP_XOR_QUAD_CurrentVersionRun_2bf8 {
  strings:
    $key_2bf8 = { 78 97 [2] 5c 99 [2] 77 b5 [2] 59 97 [2] 4d 8c [2] 42 96 [2] 5c 8b [2] 5e 8a [2] 45 8c [2] 59 8b [2] 45 a4 }

  condition:
    any of them
}