rule TTP_XOR_WriteProcessMemory_23b9 {
  strings:
    $key_23b9 = { 74 cb [2] 46 e9 [2] 40 dc [2] 6e dc [2] 51 c0 }

  condition:
    any of them
}