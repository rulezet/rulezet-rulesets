rule TTP_XOR_QUAD_CurrentVersionRun_20f8 {
  strings:
    $key_20f8 = { 73 97 [2] 57 99 [2] 7c b5 [2] 52 97 [2] 46 8c [2] 49 96 [2] 57 8b [2] 55 8a [2] 4e 8c [2] 52 8b [2] 4e a4 }

  condition:
    any of them
}