rule TTP_XOR_WriteProcessMemory_09be {
  strings:
    $key_09be = { 5e cc [2] 6c ee [2] 6a db [2] 44 db [2] 7b c7 }

  condition:
    any of them
}