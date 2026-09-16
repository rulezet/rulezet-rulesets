rule TTP_XOR_QUAD_CurrentVersionRun_2925 {
  strings:
    $key_2925 = { 7a 4a [2] 5e 44 [2] 75 68 [2] 5b 4a [2] 4f 51 [2] 40 4b [2] 5e 56 [2] 5c 57 [2] 47 51 [2] 5b 56 [2] 47 79 }

  condition:
    any of them
}