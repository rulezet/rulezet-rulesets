rule TTP_XOR_WriteProcessMemory_1001 {
  strings:
    $key_1001 = { 47 73 [2] 75 51 [2] 73 64 [2] 5d 64 [2] 62 78 }

  condition:
    any of them
}