rule TTP_XOR_QUAD_CurrentVersionRun_7a19 {
  strings:
    $key_7a19 = { 29 76 [2] 0d 78 [2] 26 54 [2] 08 76 [2] 1c 6d [2] 13 77 [2] 0d 6a [2] 0f 6b [2] 14 6d [2] 08 6a [2] 14 45 }

  condition:
    any of them
}