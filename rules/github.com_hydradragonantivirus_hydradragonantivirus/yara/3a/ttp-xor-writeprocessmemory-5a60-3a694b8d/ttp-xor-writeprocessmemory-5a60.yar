rule TTP_XOR_WriteProcessMemory_5a60 {
  strings:
    $key_5a60 = { 0d 12 [2] 3f 30 [2] 39 05 [2] 17 05 [2] 28 19 }

  condition:
    any of them
}