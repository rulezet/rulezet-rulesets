rule TTP_XOR_QUAD_CurrentVersionRun_5708 {
  strings:
    $key_5708 = { 04 67 [2] 20 69 [2] 0b 45 [2] 25 67 [2] 31 7c [2] 3e 66 [2] 20 7b [2] 22 7a [2] 39 7c [2] 25 7b [2] 39 54 }

  condition:
    any of them
}