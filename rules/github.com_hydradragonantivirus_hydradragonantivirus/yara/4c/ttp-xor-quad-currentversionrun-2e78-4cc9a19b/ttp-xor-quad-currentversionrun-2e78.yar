rule TTP_XOR_QUAD_CurrentVersionRun_2e78 {
  strings:
    $key_2e78 = { 7d 17 [2] 59 19 [2] 72 35 [2] 5c 17 [2] 48 0c [2] 47 16 [2] 59 0b [2] 5b 0a [2] 40 0c [2] 5c 0b [2] 40 24 }

  condition:
    any of them
}