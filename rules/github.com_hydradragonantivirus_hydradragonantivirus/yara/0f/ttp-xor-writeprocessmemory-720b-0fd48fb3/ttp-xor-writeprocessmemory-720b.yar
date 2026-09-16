rule TTP_XOR_WriteProcessMemory_720b {
  strings:
    $key_720b = { 25 79 [2] 17 5b [2] 11 6e [2] 3f 6e [2] 00 72 }

  condition:
    any of them
}