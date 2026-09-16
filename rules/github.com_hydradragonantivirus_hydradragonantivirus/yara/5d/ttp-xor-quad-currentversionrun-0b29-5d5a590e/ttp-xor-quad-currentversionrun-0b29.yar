rule TTP_XOR_QUAD_CurrentVersionRun_0b29 {
  strings:
    $key_0b29 = { 58 46 [2] 7c 48 [2] 57 64 [2] 79 46 [2] 6d 5d [2] 62 47 [2] 7c 5a [2] 7e 5b [2] 65 5d [2] 79 5a [2] 65 75 }

  condition:
    any of them
}