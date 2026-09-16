rule TTP_XOR_WriteProcessMemory_3fbe {
  strings:
    $key_3fbe = { 68 cc [2] 5a ee [2] 5c db [2] 72 db [2] 4d c7 }

  condition:
    any of them
}