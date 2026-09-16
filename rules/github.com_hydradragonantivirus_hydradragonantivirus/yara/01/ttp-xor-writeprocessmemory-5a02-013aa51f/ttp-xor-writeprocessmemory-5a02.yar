rule TTP_XOR_WriteProcessMemory_5a02 {
  strings:
    $key_5a02 = { 0d 70 [2] 3f 52 [2] 39 67 [2] 17 67 [2] 28 7b }

  condition:
    any of them
}