rule TTP_XOR_WriteProcessMemory_eabe {
  strings:
    $key_eabe = { bd cc [2] 8f ee [2] 89 db [2] a7 db [2] 98 c7 }

  condition:
    any of them
}