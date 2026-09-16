rule TTP_XOR_WriteProcessMemory_1de7 {
  strings:
    $key_1de7 = { 4a 95 [2] 78 b7 [2] 7e 82 [2] 50 82 [2] 6f 9e }

  condition:
    any of them
}