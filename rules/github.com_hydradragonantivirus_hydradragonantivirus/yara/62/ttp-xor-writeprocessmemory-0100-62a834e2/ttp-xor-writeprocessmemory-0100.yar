rule TTP_XOR_WriteProcessMemory_0100 {
  strings:
    $key_0100 = { 56 72 [2] 64 50 [2] 62 65 [2] 4c 65 [2] 73 79 }

  condition:
    any of them
}