rule TTP_XOR_WriteProcessMemory_2abe {
  strings:
    $key_2abe = { 7d cc [2] 4f ee [2] 49 db [2] 67 db [2] 58 c7 }

  condition:
    any of them
}