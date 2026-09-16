rule TTP_XOR_WriteProcessMemory_5a52 {
  strings:
    $key_5a52 = { 0d 20 [2] 3f 02 [2] 39 37 [2] 17 37 [2] 28 2b }

  condition:
    any of them
}