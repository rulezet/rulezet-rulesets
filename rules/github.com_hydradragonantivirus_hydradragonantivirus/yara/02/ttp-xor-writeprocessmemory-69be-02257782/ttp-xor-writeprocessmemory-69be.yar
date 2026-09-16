rule TTP_XOR_WriteProcessMemory_69be {
  strings:
    $key_69be = { 3e cc [2] 0c ee [2] 0a db [2] 24 db [2] 1b c7 }

  condition:
    any of them
}