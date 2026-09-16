rule TTP_XOR_QUAD_CurrentVersionRun_0939 {
  strings:
    $key_0939 = { 5a 56 [2] 7e 58 [2] 55 74 [2] 7b 56 [2] 6f 4d [2] 60 57 [2] 7e 4a [2] 7c 4b [2] 67 4d [2] 7b 4a [2] 67 65 }

  condition:
    any of them
}