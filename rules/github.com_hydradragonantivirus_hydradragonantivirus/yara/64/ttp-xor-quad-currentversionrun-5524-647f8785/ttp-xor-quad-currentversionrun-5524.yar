rule TTP_XOR_QUAD_CurrentVersionRun_5524 {
  strings:
    $key_5524 = { 06 4b [2] 22 45 [2] 09 69 [2] 27 4b [2] 33 50 [2] 3c 4a [2] 22 57 [2] 20 56 [2] 3b 50 [2] 27 57 [2] 3b 78 }

  condition:
    any of them
}