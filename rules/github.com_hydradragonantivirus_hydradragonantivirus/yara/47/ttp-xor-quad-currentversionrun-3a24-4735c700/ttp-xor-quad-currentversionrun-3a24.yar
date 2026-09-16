rule TTP_XOR_QUAD_CurrentVersionRun_3a24 {
  strings:
    $key_3a24 = { 69 4b [2] 4d 45 [2] 66 69 [2] 48 4b [2] 5c 50 [2] 53 4a [2] 4d 57 [2] 4f 56 [2] 54 50 [2] 48 57 [2] 54 78 }

  condition:
    any of them
}