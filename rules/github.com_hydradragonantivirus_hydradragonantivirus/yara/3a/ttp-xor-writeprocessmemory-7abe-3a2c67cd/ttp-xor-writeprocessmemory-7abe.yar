rule TTP_XOR_WriteProcessMemory_7abe {
  strings:
    $key_7abe = { 2d cc [2] 1f ee [2] 19 db [2] 37 db [2] 08 c7 }

  condition:
    any of them
}