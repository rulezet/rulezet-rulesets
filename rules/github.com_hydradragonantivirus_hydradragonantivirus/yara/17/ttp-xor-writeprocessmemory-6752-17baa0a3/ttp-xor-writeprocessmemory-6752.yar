rule TTP_XOR_WriteProcessMemory_6752 {
  strings:
    $key_6752 = { 30 20 [2] 02 02 [2] 04 37 [2] 2a 37 [2] 15 2b }

  condition:
    any of them
}