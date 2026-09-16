rule TTP_XOR_WriteProcessMemory_3001 {
  strings:
    $key_3001 = { 67 73 [2] 55 51 [2] 53 64 [2] 7d 64 [2] 42 78 }

  condition:
    any of them
}