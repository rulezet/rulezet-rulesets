rule TTP_XOR_WriteProcessMemory_5a22 {
  strings:
    $key_5a22 = { 0d 50 [2] 3f 72 [2] 39 47 [2] 17 47 [2] 28 5b }

  condition:
    any of them
}