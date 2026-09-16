rule TTP_XOR_WriteProcessMemory_e9be {
  strings:
    $key_e9be = { be cc [2] 8c ee [2] 8a db [2] a4 db [2] 9b c7 }

  condition:
    any of them
}