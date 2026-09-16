rule TTP_XOR_WriteProcessMemory_018b {
  strings:
    $key_018b = { 56 f9 [2] 64 db [2] 62 ee [2] 4c ee [2] 73 f2 }

  condition:
    any of them
}