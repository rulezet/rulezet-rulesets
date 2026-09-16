rule TTP_XOR_WriteProcessMemory_177e {
  strings:
    $key_177e = { 40 0c [2] 72 2e [2] 74 1b [2] 5a 1b [2] 65 07 }

  condition:
    any of them
}