rule TTP_XOR_QUAD_CurrentVersionRun_0925 {
  strings:
    $key_0925 = { 5a 4a [2] 7e 44 [2] 55 68 [2] 7b 4a [2] 6f 51 [2] 60 4b [2] 7e 56 [2] 7c 57 [2] 67 51 [2] 7b 56 [2] 67 79 }

  condition:
    any of them
}