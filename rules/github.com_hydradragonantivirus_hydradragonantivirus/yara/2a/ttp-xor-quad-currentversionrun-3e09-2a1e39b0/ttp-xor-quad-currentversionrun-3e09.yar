rule TTP_XOR_QUAD_CurrentVersionRun_3e09 {
  strings:
    $key_3e09 = { 6d 66 [2] 49 68 [2] 62 44 [2] 4c 66 [2] 58 7d [2] 57 67 [2] 49 7a [2] 4b 7b [2] 50 7d [2] 4c 7a [2] 50 55 }

  condition:
    any of them
}