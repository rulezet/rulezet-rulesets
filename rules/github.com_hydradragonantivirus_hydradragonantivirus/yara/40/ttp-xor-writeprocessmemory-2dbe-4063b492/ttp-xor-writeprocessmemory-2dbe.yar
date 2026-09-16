rule TTP_XOR_WriteProcessMemory_2dbe {
  strings:
    $key_2dbe = { 7a cc [2] 48 ee [2] 4e db [2] 60 db [2] 5f c7 }

  condition:
    any of them
}