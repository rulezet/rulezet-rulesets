rule TTP_XOR_WriteProcessMemory_1636 {
  strings:
    $key_1636 = { 41 44 [2] 73 66 [2] 75 53 [2] 5b 53 [2] 64 4f }

  condition:
    any of them
}