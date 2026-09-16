rule TTP_XOR_WriteProcessMemory_5a70 {
  strings:
    $key_5a70 = { 0d 02 [2] 3f 20 [2] 39 15 [2] 17 15 [2] 28 09 }

  condition:
    any of them
}