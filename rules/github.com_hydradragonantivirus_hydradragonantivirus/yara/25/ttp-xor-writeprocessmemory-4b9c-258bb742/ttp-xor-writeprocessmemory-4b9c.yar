rule TTP_XOR_WriteProcessMemory_4b9c {
  strings:
    $key_4b9c = { 1c ee [2] 2e cc [2] 28 f9 [2] 06 f9 [2] 39 e5 }

  condition:
    any of them
}