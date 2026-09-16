rule TTP_XOR_WriteProcessMemory_13b9 {
  strings:
    $key_13b9 = { 44 cb [2] 76 e9 [2] 70 dc [2] 5e dc [2] 61 c0 }

  condition:
    any of them
}