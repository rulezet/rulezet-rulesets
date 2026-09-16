rule TTP_XOR_WriteProcessMemory_0041 {
  strings:
    $key_0041 = { 57 33 [2] 65 11 [2] 63 24 [2] 4d 24 [2] 72 38 }

  condition:
    any of them
}