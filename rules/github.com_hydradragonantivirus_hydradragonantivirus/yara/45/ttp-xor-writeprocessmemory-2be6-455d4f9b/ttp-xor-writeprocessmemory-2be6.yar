rule TTP_XOR_WriteProcessMemory_2be6 {
  strings:
    $key_2be6 = { 7c 94 [2] 4e b6 [2] 48 83 [2] 66 83 [2] 59 9f }

  condition:
    any of them
}