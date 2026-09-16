rule TTP_XOR_QUAD_CurrentVersionRun_4e08 {
  strings:
    $key_4e08 = { 1d 67 [2] 39 69 [2] 12 45 [2] 3c 67 [2] 28 7c [2] 27 66 [2] 39 7b [2] 3b 7a [2] 20 7c [2] 3c 7b [2] 20 54 }

  condition:
    any of them
}