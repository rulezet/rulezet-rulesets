rule TTP_XOR_QUAD_CurrentVersionRun_f278 {
  strings:
    $key_f278 = { a1 17 [2] 85 19 [2] ae 35 [2] 80 17 [2] 94 0c [2] 9b 16 [2] 85 0b [2] 87 0a [2] 9c 0c [2] 80 0b [2] 9c 24 }

  condition:
    any of them
}