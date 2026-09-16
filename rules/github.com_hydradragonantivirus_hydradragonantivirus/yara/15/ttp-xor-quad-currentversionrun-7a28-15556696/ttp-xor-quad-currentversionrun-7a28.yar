rule TTP_XOR_QUAD_CurrentVersionRun_7a28 {
  strings:
    $key_7a28 = { 29 47 [2] 0d 49 [2] 26 65 [2] 08 47 [2] 1c 5c [2] 13 46 [2] 0d 5b [2] 0f 5a [2] 14 5c [2] 08 5b [2] 14 74 }

  condition:
    any of them
}