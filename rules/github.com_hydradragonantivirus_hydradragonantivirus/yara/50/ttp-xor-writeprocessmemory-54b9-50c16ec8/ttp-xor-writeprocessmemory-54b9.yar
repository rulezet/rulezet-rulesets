rule TTP_XOR_WriteProcessMemory_54b9 {
  strings:
    $key_54b9 = { 03 cb [2] 31 e9 [2] 37 dc [2] 19 dc [2] 26 c0 }

  condition:
    any of them
}