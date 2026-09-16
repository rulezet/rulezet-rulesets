rule TTP_XOR_WriteProcessMemory_49be {
  strings:
    $key_49be = { 1e cc [2] 2c ee [2] 2a db [2] 04 db [2] 3b c7 }

  condition:
    any of them
}