rule TTP_XOR_QUAD_CurrentVersionRun_5039 {
  strings:
    $key_5039 = { 03 56 [2] 27 58 [2] 0c 74 [2] 22 56 [2] 36 4d [2] 39 57 [2] 27 4a [2] 25 4b [2] 3e 4d [2] 22 4a [2] 3e 65 }

  condition:
    any of them
}