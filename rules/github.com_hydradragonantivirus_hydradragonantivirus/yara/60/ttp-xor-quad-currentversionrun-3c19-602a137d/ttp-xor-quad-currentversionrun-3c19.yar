rule TTP_XOR_QUAD_CurrentVersionRun_3c19 {
  strings:
    $key_3c19 = { 6f 76 [2] 4b 78 [2] 60 54 [2] 4e 76 [2] 5a 6d [2] 55 77 [2] 4b 6a [2] 49 6b [2] 52 6d [2] 4e 6a [2] 52 45 }

  condition:
    any of them
}