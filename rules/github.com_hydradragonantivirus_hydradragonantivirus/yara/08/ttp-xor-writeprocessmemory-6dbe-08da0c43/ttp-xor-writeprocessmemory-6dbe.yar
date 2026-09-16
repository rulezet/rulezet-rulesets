rule TTP_XOR_WriteProcessMemory_6dbe {
  strings:
    $key_6dbe = { 3a cc [2] 08 ee [2] 0e db [2] 20 db [2] 1f c7 }

  condition:
    any of them
}