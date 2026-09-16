rule TTP_XOR_WriteProcessMemory_1626 {
  strings:
    $key_1626 = { 41 54 [2] 73 76 [2] 75 43 [2] 5b 43 [2] 64 5f }

  condition:
    any of them
}