rule TTP_XOR_WriteProcessMemory_2bb9 {
  strings:
    $key_2bb9 = { 7c cb [2] 4e e9 [2] 48 dc [2] 66 dc [2] 59 c0 }

  condition:
    any of them
}