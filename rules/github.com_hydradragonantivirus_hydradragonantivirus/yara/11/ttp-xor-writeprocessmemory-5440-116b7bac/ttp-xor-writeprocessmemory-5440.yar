rule TTP_XOR_WriteProcessMemory_5440 {
  strings:
    $key_5440 = { 03 32 [2] 31 10 [2] 37 25 [2] 19 25 [2] 26 39 }

  condition:
    any of them
}