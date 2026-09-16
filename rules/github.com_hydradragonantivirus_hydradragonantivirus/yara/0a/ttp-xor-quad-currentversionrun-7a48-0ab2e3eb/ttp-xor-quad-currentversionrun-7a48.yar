rule TTP_XOR_QUAD_CurrentVersionRun_7a48 {
  strings:
    $key_7a48 = { 29 27 [2] 0d 29 [2] 26 05 [2] 08 27 [2] 1c 3c [2] 13 26 [2] 0d 3b [2] 0f 3a [2] 14 3c [2] 08 3b [2] 14 14 }

  condition:
    any of them
}