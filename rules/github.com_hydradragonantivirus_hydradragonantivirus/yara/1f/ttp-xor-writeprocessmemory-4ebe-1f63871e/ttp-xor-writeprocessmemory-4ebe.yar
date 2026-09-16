rule TTP_XOR_WriteProcessMemory_4ebe {
  strings:
    $key_4ebe = { 19 cc [2] 2b ee [2] 2d db [2] 03 db [2] 3c c7 }

  condition:
    any of them
}