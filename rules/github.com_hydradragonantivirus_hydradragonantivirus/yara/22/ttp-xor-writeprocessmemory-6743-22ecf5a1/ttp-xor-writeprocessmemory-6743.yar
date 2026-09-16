rule TTP_XOR_WriteProcessMemory_6743 {
  strings:
    $key_6743 = { 30 31 [2] 02 13 [2] 04 26 [2] 2a 26 [2] 15 3a }

  condition:
    any of them
}