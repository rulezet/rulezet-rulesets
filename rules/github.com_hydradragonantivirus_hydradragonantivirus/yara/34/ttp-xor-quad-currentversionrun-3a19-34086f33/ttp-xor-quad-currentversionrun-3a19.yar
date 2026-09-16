rule TTP_XOR_QUAD_CurrentVersionRun_3a19 {
  strings:
    $key_3a19 = { 69 76 [2] 4d 78 [2] 66 54 [2] 48 76 [2] 5c 6d [2] 53 77 [2] 4d 6a [2] 4f 6b [2] 54 6d [2] 48 6a [2] 54 45 }

  condition:
    any of them
}