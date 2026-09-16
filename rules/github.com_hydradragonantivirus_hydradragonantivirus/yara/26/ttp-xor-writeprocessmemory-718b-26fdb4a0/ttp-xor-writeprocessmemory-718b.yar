rule TTP_XOR_WriteProcessMemory_718b {
  strings:
    $key_718b = { 26 f9 [2] 14 db [2] 12 ee [2] 3c ee [2] 03 f2 }

  condition:
    any of them
}