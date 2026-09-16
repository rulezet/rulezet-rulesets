rule TTP_XOR_QUAD_CurrentVersionRun_6f08 {
  strings:
    $key_6f08 = { 3c 67 [2] 18 69 [2] 33 45 [2] 1d 67 [2] 09 7c [2] 06 66 [2] 18 7b [2] 1a 7a [2] 01 7c [2] 1d 7b [2] 01 54 }

  condition:
    any of them
}