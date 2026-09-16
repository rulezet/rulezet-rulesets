rule TTP_XOR_QUAD_CurrentVersionRun_3945 {
  strings:
    $key_3945 = { 6a 2a [2] 4e 24 [2] 65 08 [2] 4b 2a [2] 5f 31 [2] 50 2b [2] 4e 36 [2] 4c 37 [2] 57 31 [2] 4b 36 [2] 57 19 }

  condition:
    any of them
}