rule TTP_XOR_WriteProcessMemory_f9be {
  strings:
    $key_f9be = { ae cc [2] 9c ee [2] 9a db [2] b4 db [2] 8b c7 }

  condition:
    any of them
}