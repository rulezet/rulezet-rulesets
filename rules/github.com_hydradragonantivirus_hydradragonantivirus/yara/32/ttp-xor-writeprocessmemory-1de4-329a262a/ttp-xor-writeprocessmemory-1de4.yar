rule TTP_XOR_WriteProcessMemory_1de4 {
  strings:
    $key_1de4 = { 4a 96 [2] 78 b4 [2] 7e 81 [2] 50 81 [2] 6f 9d }

  condition:
    any of them
}