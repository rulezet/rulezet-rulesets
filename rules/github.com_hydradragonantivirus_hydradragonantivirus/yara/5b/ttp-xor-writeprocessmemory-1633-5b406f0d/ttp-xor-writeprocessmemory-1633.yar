rule TTP_XOR_WriteProcessMemory_1633 {
  strings:
    $key_1633 = { 41 41 [2] 73 63 [2] 75 56 [2] 5b 56 [2] 64 4a }

  condition:
    any of them
}