rule TTP_XOR_WriteProcessMemory_6733 {
  strings:
    $key_6733 = { 30 41 [2] 02 63 [2] 04 56 [2] 2a 56 [2] 15 4a }

  condition:
    any of them
}