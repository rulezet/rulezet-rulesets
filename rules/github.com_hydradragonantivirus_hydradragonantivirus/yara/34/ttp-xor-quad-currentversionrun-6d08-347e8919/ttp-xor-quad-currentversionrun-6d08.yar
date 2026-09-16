rule TTP_XOR_QUAD_CurrentVersionRun_6d08 {
  strings:
    $key_6d08 = { 3e 67 [2] 1a 69 [2] 31 45 [2] 1f 67 [2] 0b 7c [2] 04 66 [2] 1a 7b [2] 18 7a [2] 03 7c [2] 1f 7b [2] 03 54 }

  condition:
    any of them
}