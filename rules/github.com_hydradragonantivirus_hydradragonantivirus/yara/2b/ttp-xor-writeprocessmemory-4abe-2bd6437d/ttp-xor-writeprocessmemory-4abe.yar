rule TTP_XOR_WriteProcessMemory_4abe {
  strings:
    $key_4abe = { 1d cc [2] 2f ee [2] 29 db [2] 07 db [2] 38 c7 }

  condition:
    any of them
}