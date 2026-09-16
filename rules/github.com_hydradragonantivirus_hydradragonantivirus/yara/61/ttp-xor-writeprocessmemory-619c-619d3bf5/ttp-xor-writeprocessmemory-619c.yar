rule TTP_XOR_WriteProcessMemory_619c {
  strings:
    $key_619c = { 36 ee [2] 04 cc [2] 02 f9 [2] 2c f9 [2] 13 e5 }

  condition:
    any of them
}