rule TTP_XOR_QUAD_CurrentVersionRun_7939 {
  strings:
    $key_7939 = { 2a 56 [2] 0e 58 [2] 25 74 [2] 0b 56 [2] 1f 4d [2] 10 57 [2] 0e 4a [2] 0c 4b [2] 17 4d [2] 0b 4a [2] 17 65 }

  condition:
    any of them
}