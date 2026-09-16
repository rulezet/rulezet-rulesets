rule TTP_XOR_WriteProcessMemory_0900 {
  strings:
    $key_0900 = { 5e 72 [2] 6c 50 [2] 6a 65 [2] 44 65 [2] 7b 79 }

  condition:
    any of them
}