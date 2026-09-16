rule TTP_XOR_QUAD_CurrentVersionRun_2728 {
  strings:
    $key_2728 = { 74 47 [2] 50 49 [2] 7b 65 [2] 55 47 [2] 41 5c [2] 4e 46 [2] 50 5b [2] 52 5a [2] 49 5c [2] 55 5b [2] 49 74 }

  condition:
    any of them
}