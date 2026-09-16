rule TTP_XOR_QUAD_CurrentVersionRun_7a29 {
  strings:
    $key_7a29 = { 29 46 [2] 0d 48 [2] 26 64 [2] 08 46 [2] 1c 5d [2] 13 47 [2] 0d 5a [2] 0f 5b [2] 14 5d [2] 08 5a [2] 14 75 }

  condition:
    any of them
}