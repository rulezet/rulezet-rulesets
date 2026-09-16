rule TTP_XOR_WriteProcessMemory_19be {
  strings:
    $key_19be = { 4e cc [2] 7c ee [2] 7a db [2] 54 db [2] 6b c7 }

  condition:
    any of them
}