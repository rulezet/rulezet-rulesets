rule TTP_XOR_WriteProcessMemory_0abe {
  strings:
    $key_0abe = { 5d cc [2] 6f ee [2] 69 db [2] 47 db [2] 78 c7 }

  condition:
    any of them
}