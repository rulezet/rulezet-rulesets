rule TTP_XOR_WriteProcessMemory_6fbe {
  strings:
    $key_6fbe = { 38 cc [2] 0a ee [2] 0c db [2] 22 db [2] 1d c7 }

  condition:
    any of them
}