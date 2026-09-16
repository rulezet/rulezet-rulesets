rule TTP_XOR_WriteProcessMemory_008b {
  strings:
    $key_008b = { 57 f9 [2] 65 db [2] 63 ee [2] 4d ee [2] 72 f2 }

  condition:
    any of them
}