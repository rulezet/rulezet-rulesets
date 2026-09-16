rule TTP_XOR_WriteProcessMemory_41b9 {
  strings:
    $key_41b9 = { 16 cb [2] 24 e9 [2] 22 dc [2] 0c dc [2] 33 c0 }

  condition:
    any of them
}