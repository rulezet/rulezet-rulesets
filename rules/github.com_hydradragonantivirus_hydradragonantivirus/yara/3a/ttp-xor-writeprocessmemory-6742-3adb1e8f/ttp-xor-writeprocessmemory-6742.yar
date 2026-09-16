rule TTP_XOR_WriteProcessMemory_6742 {
  strings:
    $key_6742 = { 30 30 [2] 02 12 [2] 04 27 [2] 2a 27 [2] 15 3b }

  condition:
    any of them
}