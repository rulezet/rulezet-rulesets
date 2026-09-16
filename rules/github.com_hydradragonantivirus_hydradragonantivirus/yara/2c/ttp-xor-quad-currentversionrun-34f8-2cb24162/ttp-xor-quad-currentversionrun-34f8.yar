rule TTP_XOR_QUAD_CurrentVersionRun_34f8 {
  strings:
    $key_34f8 = { 67 97 [2] 43 99 [2] 68 b5 [2] 46 97 [2] 52 8c [2] 5d 96 [2] 43 8b [2] 41 8a [2] 5a 8c [2] 46 8b [2] 5a a4 }

  condition:
    any of them
}