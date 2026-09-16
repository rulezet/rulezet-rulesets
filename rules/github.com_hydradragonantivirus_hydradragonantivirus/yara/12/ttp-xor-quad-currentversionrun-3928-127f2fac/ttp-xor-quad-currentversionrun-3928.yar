rule TTP_XOR_QUAD_CurrentVersionRun_3928 {
  strings:
    $key_3928 = { 6a 47 [2] 4e 49 [2] 65 65 [2] 4b 47 [2] 5f 5c [2] 50 46 [2] 4e 5b [2] 4c 5a [2] 57 5c [2] 4b 5b [2] 57 74 }

  condition:
    any of them
}