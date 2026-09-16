rule TTP_XOR_QUAD_CurrentVersionRun_1b08 {
  strings:
    $key_1b08 = { 48 67 [2] 6c 69 [2] 47 45 [2] 69 67 [2] 7d 7c [2] 72 66 [2] 6c 7b [2] 6e 7a [2] 75 7c [2] 69 7b [2] 75 54 }

  condition:
    any of them
}