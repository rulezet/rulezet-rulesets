rule TTP_XOR_WriteProcessMemory_3b9c {
  strings:
    $key_3b9c = { 6c ee [2] 5e cc [2] 58 f9 [2] 76 f9 [2] 49 e5 }

  condition:
    any of them
}