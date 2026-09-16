rule TTP_XOR_WriteProcessMemory_1653 {
  strings:
    $key_1653 = { 41 21 [2] 73 03 [2] 75 36 [2] 5b 36 [2] 64 2a }

  condition:
    any of them
}