rule TTP_XOR_WriteProcessMemory_3ebe {
  strings:
    $key_3ebe = { 69 cc [2] 5b ee [2] 5d db [2] 73 db [2] 4c c7 }

  condition:
    any of them
}