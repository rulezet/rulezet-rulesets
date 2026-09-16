rule TTP_XOR_WriteProcessMemory_1701 {
  strings:
    $key_1701 = { 40 73 [2] 72 51 [2] 74 64 [2] 5a 64 [2] 65 78 }

  condition:
    any of them
}