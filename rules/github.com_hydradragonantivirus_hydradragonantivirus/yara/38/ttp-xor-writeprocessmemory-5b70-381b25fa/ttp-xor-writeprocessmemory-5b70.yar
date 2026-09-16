rule TTP_XOR_WriteProcessMemory_5b70 {
  strings:
    $key_5b70 = { 0c 02 [2] 3e 20 [2] 38 15 [2] 16 15 [2] 29 09 }

  condition:
    any of them
}