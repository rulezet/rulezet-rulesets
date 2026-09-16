rule TTP_XOR_WriteProcessMemory_76a5 {
  strings:
    $key_76a5 = { 21 d7 [2] 13 f5 [2] 15 c0 [2] 3b c0 [2] 04 dc }

  condition:
    any of them
}