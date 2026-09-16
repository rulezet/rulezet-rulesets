rule TTP_XOR_QUAD_CurrentVersionRun_6578 {
  strings:
    $key_6578 = { 36 17 [2] 12 19 [2] 39 35 [2] 17 17 [2] 03 0c [2] 0c 16 [2] 12 0b [2] 10 0a [2] 0b 0c [2] 17 0b [2] 0b 24 }

  condition:
    any of them
}