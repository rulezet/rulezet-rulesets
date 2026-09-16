rule TTP_XOR_QUAD_CurrentVersionRun_3938 {
  strings:
    $key_3938 = { 6a 57 [2] 4e 59 [2] 65 75 [2] 4b 57 [2] 5f 4c [2] 50 56 [2] 4e 4b [2] 4c 4a [2] 57 4c [2] 4b 4b [2] 57 64 }

  condition:
    any of them
}