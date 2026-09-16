rule TTP_XOR_WriteProcessMemory_76a4 {
  strings:
    $key_76a4 = { 21 d6 [2] 13 f4 [2] 15 c1 [2] 3b c1 [2] 04 dd }

  condition:
    any of them
}