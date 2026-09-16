rule TTP_XOR_WriteProcessMemory_0fbe {
  strings:
    $key_0fbe = { 58 cc [2] 6a ee [2] 6c db [2] 42 db [2] 7d c7 }

  condition:
    any of them
}