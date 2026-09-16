rule TTP_XOR_WriteProcessMemory_0153 {
  strings:
    $key_0153 = { 56 21 [2] 64 03 [2] 62 36 [2] 4c 36 [2] 73 2a }

  condition:
    any of them
}