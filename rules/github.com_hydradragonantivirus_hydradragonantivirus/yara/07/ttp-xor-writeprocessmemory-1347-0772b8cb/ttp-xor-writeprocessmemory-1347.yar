rule TTP_XOR_WriteProcessMemory_1347 {
  strings:
    $key_1347 = { 44 35 [2] 76 17 [2] 70 22 [2] 5e 22 [2] 61 3e }

  condition:
    any of them
}