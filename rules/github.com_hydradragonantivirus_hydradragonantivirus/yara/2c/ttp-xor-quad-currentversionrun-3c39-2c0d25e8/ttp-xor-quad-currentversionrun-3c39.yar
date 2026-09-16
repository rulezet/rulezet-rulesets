rule TTP_XOR_QUAD_CurrentVersionRun_3c39 {
  strings:
    $key_3c39 = { 6f 56 [2] 4b 58 [2] 60 74 [2] 4e 56 [2] 5a 4d [2] 55 57 [2] 4b 4a [2] 49 4b [2] 52 4d [2] 4e 4a [2] 52 65 }

  condition:
    any of them
}