rule TTP_XOR_WriteProcessMemory_4633 {
  strings:
    $key_4633 = { 11 41 [2] 23 63 [2] 25 56 [2] 0b 56 [2] 34 4a }

  condition:
    any of them
}