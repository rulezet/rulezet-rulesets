rule TTP_XOR_QUAD_CurrentVersionRun_3129 {
  strings:
    $key_3129 = { 62 46 [2] 46 48 [2] 6d 64 [2] 43 46 [2] 57 5d [2] 58 47 [2] 46 5a [2] 44 5b [2] 5f 5d [2] 43 5a [2] 5f 75 }

  condition:
    any of them
}