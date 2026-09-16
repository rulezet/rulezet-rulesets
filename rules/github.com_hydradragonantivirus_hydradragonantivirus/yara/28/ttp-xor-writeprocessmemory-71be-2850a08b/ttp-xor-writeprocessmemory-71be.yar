rule TTP_XOR_WriteProcessMemory_71be {
  strings:
    $key_71be = { 26 cc [2] 14 ee [2] 12 db [2] 3c db [2] 03 c7 }

  condition:
    any of them
}