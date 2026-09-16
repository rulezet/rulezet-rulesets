rule TTP_XOR_WriteProcessMemory_1601 {
  strings:
    $key_1601 = { 41 73 [2] 73 51 [2] 75 64 [2] 5b 64 [2] 64 78 }

  condition:
    any of them
}