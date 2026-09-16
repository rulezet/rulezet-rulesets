rule TTP_XOR_QUAD_CurrentVersionRun_2be9 {
  strings:
    $key_2be9 = { 78 86 [2] 5c 88 [2] 77 a4 [2] 59 86 [2] 4d 9d [2] 42 87 [2] 5c 9a [2] 5e 9b [2] 45 9d [2] 59 9a [2] 45 b5 }

  condition:
    any of them
}