rule TTP_XOR_WriteProcessMemory_3b70 {
  strings:
    $key_3b70 = { 6c 02 [2] 5e 20 [2] 58 15 [2] 76 15 [2] 49 09 }

  condition:
    any of them
}