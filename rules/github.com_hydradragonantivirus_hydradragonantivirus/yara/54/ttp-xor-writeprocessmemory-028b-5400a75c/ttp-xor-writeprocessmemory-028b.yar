rule TTP_XOR_WriteProcessMemory_028b {
  strings:
    $key_028b = { 55 f9 [2] 67 db [2] 61 ee [2] 4f ee [2] 70 f2 }

  condition:
    any of them
}