rule TTP_XOR_WriteProcessMemory_7601 {
  strings:
    $key_7601 = { 21 73 [2] 13 51 [2] 15 64 [2] 3b 64 [2] 04 78 }

  condition:
    any of them
}