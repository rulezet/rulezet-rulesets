rule TTP_XOR_WriteProcessMemory_1fbe {
  strings:
    $key_1fbe = { 48 cc [2] 7a ee [2] 7c db [2] 52 db [2] 6d c7 }

  condition:
    any of them
}