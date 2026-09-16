rule TTP_XOR_WriteProcessMemory_5b9c {
  strings:
    $key_5b9c = { 0c ee [2] 3e cc [2] 38 f9 [2] 16 f9 [2] 29 e5 }

  condition:
    any of them
}