rule TTP_XOR_QUAD_CurrentVersionRun_3c48 {
  strings:
    $key_3c48 = { 6f 27 [2] 4b 29 [2] 60 05 [2] 4e 27 [2] 5a 3c [2] 55 26 [2] 4b 3b [2] 49 3a [2] 52 3c [2] 4e 3b [2] 52 14 }

  condition:
    any of them
}