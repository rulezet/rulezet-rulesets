rule TTP_XOR_WriteProcessMemory_39be {
  strings:
    $key_39be = { 6e cc [2] 5c ee [2] 5a db [2] 74 db [2] 4b c7 }

  condition:
    any of them
}