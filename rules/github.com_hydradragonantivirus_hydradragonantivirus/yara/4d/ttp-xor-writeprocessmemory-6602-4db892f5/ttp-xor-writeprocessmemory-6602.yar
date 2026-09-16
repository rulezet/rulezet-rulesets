rule TTP_XOR_WriteProcessMemory_6602 {
  strings:
    $key_6602 = { 31 70 [2] 03 52 [2] 05 67 [2] 2b 67 [2] 14 7b }

  condition:
    any of them
}