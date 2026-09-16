rule TTP_XOR_QUAD_CurrentVersionRun_3ce4 {
  strings:
    $key_3ce4 = { 6f 8b [2] 4b 85 [2] 60 a9 [2] 4e 8b [2] 5a 90 [2] 55 8a [2] 4b 97 [2] 49 96 [2] 52 90 [2] 4e 97 [2] 52 b8 }

  condition:
    any of them
}