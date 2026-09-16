rule TTP_XOR_QUAD_CurrentVersionRun_2018 {
  strings:
    $key_2018 = { 73 77 [2] 57 79 [2] 7c 55 [2] 52 77 [2] 46 6c [2] 49 76 [2] 57 6b [2] 55 6a [2] 4e 6c [2] 52 6b [2] 4e 44 }

  condition:
    any of them
}