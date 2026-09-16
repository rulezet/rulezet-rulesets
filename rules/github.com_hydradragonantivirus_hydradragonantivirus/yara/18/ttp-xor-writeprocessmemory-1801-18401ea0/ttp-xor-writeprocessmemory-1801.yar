rule TTP_XOR_WriteProcessMemory_1801 {
  strings:
    $key_1801 = { 4f 73 [2] 7d 51 [2] 7b 64 [2] 55 64 [2] 6a 78 }

  condition:
    any of them
}