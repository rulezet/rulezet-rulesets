rule TTP_XOR_QUAD_CurrentVersionRun_6278 {
  strings:
    $key_6278 = { 31 17 [2] 15 19 [2] 3e 35 [2] 10 17 [2] 04 0c [2] 0b 16 [2] 15 0b [2] 17 0a [2] 0c 0c [2] 10 0b [2] 0c 24 }

  condition:
    any of them
}