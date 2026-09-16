rule TTP_XOR_WriteProcessMemory_32b9 {
  strings:
    $key_32b9 = { 65 cb [2] 57 e9 [2] 51 dc [2] 7f dc [2] 40 c0 }

  condition:
    any of them
}