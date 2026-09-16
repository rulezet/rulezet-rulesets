rule TTP_XOR_QUAD_CurrentVersionRun_20f9 {
  strings:
    $key_20f9 = { 73 96 [2] 57 98 [2] 7c b4 [2] 52 96 [2] 46 8d [2] 49 97 [2] 57 8a [2] 55 8b [2] 4e 8d [2] 52 8a [2] 4e a5 }

  condition:
    any of them
}