rule TTP_XOR_QUAD_CurrentVersionRun_5808 {
  strings:
    $key_5808 = { 0b 67 [2] 2f 69 [2] 04 45 [2] 2a 67 [2] 3e 7c [2] 31 66 [2] 2f 7b [2] 2d 7a [2] 36 7c [2] 2a 7b [2] 36 54 }

  condition:
    any of them
}