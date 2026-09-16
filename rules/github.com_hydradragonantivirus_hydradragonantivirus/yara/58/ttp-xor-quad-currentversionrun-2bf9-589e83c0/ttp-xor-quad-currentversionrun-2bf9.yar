rule TTP_XOR_QUAD_CurrentVersionRun_2bf9 {
  strings:
    $key_2bf9 = { 78 96 [2] 5c 98 [2] 77 b4 [2] 59 96 [2] 4d 8d [2] 42 97 [2] 5c 8a [2] 5e 8b [2] 45 8d [2] 59 8a [2] 45 a5 }

  condition:
    any of them
}