rule TTP_XOR_WriteProcessMemory_4001 {
  strings:
    $key_4001 = { 17 73 [2] 25 51 [2] 23 64 [2] 0d 64 [2] 32 78 }

  condition:
    any of them
}