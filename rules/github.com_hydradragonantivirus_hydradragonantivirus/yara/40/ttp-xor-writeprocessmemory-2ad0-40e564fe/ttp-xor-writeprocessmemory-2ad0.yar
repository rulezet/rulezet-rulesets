rule TTP_XOR_WriteProcessMemory_2ad0 {
  strings:
    $key_2ad0 = { 7d a2 [2] 4f 80 [2] 49 b5 [2] 67 b5 [2] 58 a9 }

  condition:
    any of them
}