rule TTP_XOR_WriteProcessMemory_08e4 {
  strings:
    $key_08e4 = { 5f 96 [2] 6d b4 [2] 6b 81 [2] 45 81 [2] 7a 9d }

  condition:
    any of them
}