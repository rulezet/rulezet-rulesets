rule TTP_XOR_QUAD_CurrentVersionRun_3e39 {
  strings:
    $key_3e39 = { 6d 56 [2] 49 58 [2] 62 74 [2] 4c 56 [2] 58 4d [2] 57 57 [2] 49 4a [2] 4b 4b [2] 50 4d [2] 4c 4a [2] 50 65 }

  condition:
    any of them
}