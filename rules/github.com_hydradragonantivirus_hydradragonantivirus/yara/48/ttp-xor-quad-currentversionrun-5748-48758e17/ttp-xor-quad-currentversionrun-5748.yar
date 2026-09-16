rule TTP_XOR_QUAD_CurrentVersionRun_5748 {
  strings:
    $key_5748 = { 04 27 [2] 20 29 [2] 0b 05 [2] 25 27 [2] 31 3c [2] 3e 26 [2] 20 3b [2] 22 3a [2] 39 3c [2] 25 3b [2] 39 14 }

  condition:
    any of them
}