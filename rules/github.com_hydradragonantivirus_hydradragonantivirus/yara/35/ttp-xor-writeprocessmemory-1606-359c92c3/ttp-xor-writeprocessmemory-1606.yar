rule TTP_XOR_WriteProcessMemory_1606 {
  strings:
    $key_1606 = { 41 74 [2] 73 56 [2] 75 63 [2] 5b 63 [2] 64 7f }

  condition:
    any of them
}