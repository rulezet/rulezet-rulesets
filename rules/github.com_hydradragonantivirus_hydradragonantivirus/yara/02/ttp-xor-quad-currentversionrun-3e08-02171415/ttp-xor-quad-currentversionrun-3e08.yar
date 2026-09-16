rule TTP_XOR_QUAD_CurrentVersionRun_3e08 {
  strings:
    $key_3e08 = { 6d 67 [2] 49 69 [2] 62 45 [2] 4c 67 [2] 58 7c [2] 57 66 [2] 49 7b [2] 4b 7a [2] 50 7c [2] 4c 7b [2] 50 54 }

  condition:
    any of them
}