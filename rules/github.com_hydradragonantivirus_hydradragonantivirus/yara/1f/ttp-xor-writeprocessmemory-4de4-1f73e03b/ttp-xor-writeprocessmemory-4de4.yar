rule TTP_XOR_WriteProcessMemory_4de4 {
  strings:
    $key_4de4 = { 1a 96 [2] 28 b4 [2] 2e 81 [2] 00 81 [2] 3f 9d }

  condition:
    any of them
}