rule TTP_XOR_WriteProcessMemory_1071 {
  strings:
    $key_1071 = { 47 03 [2] 75 21 [2] 73 14 [2] 5d 14 [2] 62 08 }

  condition:
    any of them
}