rule TTP_XOR_WriteProcessMemory_aabe {
  strings:
    $key_aabe = { fd cc [2] cf ee [2] c9 db [2] e7 db [2] d8 c7 }

  condition:
    any of them
}