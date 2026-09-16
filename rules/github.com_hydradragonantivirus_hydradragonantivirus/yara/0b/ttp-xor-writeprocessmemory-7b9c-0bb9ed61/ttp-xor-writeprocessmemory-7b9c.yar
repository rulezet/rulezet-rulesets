rule TTP_XOR_WriteProcessMemory_7b9c {
  strings:
    $key_7b9c = { 2c ee [2] 1e cc [2] 18 f9 [2] 36 f9 [2] 09 e5 }

  condition:
    any of them
}