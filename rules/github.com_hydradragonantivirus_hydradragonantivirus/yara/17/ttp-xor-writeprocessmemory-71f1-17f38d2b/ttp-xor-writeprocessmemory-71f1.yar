rule TTP_XOR_WriteProcessMemory_71f1 {
  strings:
    $key_71f1 = { 26 83 [2] 14 a1 [2] 12 94 [2] 3c 94 [2] 03 88 }

  condition:
    any of them
}