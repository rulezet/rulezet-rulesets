rule TTP_XOR_QUAD_CurrentVersionRun_3a08 {
  strings:
    $key_3a08 = { 69 67 [2] 4d 69 [2] 66 45 [2] 48 67 [2] 5c 7c [2] 53 66 [2] 4d 7b [2] 4f 7a [2] 54 7c [2] 48 7b [2] 54 54 }

  condition:
    any of them
}