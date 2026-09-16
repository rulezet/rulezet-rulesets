rule TTP_XOR_QUAD_CurrentVersionRun_2a29 {
  strings:
    $key_2a29 = { 79 46 [2] 5d 48 [2] 76 64 [2] 58 46 [2] 4c 5d [2] 43 47 [2] 5d 5a [2] 5f 5b [2] 44 5d [2] 58 5a [2] 44 75 }

  condition:
    any of them
}