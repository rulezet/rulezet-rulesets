rule TTP_XOR_WriteProcessMemory_32be {
  strings:
    $key_32be = { 65 cc [2] 57 ee [2] 51 db [2] 7f db [2] 40 c7 }

  condition:
    any of them
}