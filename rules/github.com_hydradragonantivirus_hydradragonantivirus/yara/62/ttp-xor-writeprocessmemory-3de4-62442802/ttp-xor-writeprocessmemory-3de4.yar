rule TTP_XOR_WriteProcessMemory_3de4 {
  strings:
    $key_3de4 = { 6a 96 [2] 58 b4 [2] 5e 81 [2] 70 81 [2] 4f 9d }

  condition:
    any of them
}