rule TTP_XOR_QUAD_CurrentVersionRun_3925 {
  strings:
    $key_3925 = { 6a 4a [2] 4e 44 [2] 65 68 [2] 4b 4a [2] 5f 51 [2] 50 4b [2] 4e 56 [2] 4c 57 [2] 57 51 [2] 4b 56 [2] 57 79 }

  condition:
    any of them
}