rule TTP_XOR_WriteProcessMemory_6be6 {
  strings:
    $key_6be6 = { 3c 94 [2] 0e b6 [2] 08 83 [2] 26 83 [2] 19 9f }

  condition:
    any of them
}