rule TTP_XOR_WriteProcessMemory_7fbe {
  strings:
    $key_7fbe = { 28 cc [2] 1a ee [2] 1c db [2] 32 db [2] 0d c7 }

  condition:
    any of them
}