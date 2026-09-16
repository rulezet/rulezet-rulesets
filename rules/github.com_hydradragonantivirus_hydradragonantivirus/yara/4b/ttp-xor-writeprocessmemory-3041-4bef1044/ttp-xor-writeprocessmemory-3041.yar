rule TTP_XOR_WriteProcessMemory_3041 {
  strings:
    $key_3041 = { 67 33 [2] 55 11 [2] 53 24 [2] 7d 24 [2] 42 38 }

  condition:
    any of them
}