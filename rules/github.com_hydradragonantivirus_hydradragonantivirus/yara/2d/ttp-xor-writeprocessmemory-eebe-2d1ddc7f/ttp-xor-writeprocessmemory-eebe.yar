rule TTP_XOR_WriteProcessMemory_eebe {
  strings:
    $key_eebe = { b9 cc [2] 8b ee [2] 8d db [2] a3 db [2] 9c c7 }

  condition:
    any of them
}