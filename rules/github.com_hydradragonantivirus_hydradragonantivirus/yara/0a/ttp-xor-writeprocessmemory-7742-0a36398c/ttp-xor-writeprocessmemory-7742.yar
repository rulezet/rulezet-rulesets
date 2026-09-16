rule TTP_XOR_WriteProcessMemory_7742 {
  strings:
    $key_7742 = { 20 30 [2] 12 12 [2] 14 27 [2] 3a 27 [2] 05 3b }

  condition:
    any of them
}