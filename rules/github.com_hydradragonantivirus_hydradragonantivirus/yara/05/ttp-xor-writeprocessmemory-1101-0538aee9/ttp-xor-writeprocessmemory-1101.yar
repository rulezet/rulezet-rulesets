rule TTP_XOR_WriteProcessMemory_1101 {
  strings:
    $key_1101 = { 46 73 [2] 74 51 [2] 72 64 [2] 5c 64 [2] 63 78 }

  condition:
    any of them
}