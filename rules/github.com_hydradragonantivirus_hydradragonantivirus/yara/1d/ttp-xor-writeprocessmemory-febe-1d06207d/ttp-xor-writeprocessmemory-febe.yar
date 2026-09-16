rule TTP_XOR_WriteProcessMemory_febe {
  strings:
    $key_febe = { a9 cc [2] 9b ee [2] 9d db [2] b3 db [2] 8c c7 }

  condition:
    any of them
}