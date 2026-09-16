rule TTP_XOR_WriteProcessMemory_1de6 {
  strings:
    $key_1de6 = { 4a 94 [2] 78 b6 [2] 7e 83 [2] 50 83 [2] 6f 9f }

  condition:
    any of them
}