rule TTP_XOR_WriteProcessMemory_158b {
  strings:
    $key_158b = { 42 f9 [2] 70 db [2] 76 ee [2] 58 ee [2] 67 f2 }

  condition:
    any of them
}