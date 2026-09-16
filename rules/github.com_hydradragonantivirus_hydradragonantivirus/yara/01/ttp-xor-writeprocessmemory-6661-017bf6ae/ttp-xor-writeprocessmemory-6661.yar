rule TTP_XOR_WriteProcessMemory_6661 {
  strings:
    $key_6661 = { 31 13 [2] 03 31 [2] 05 04 [2] 2b 04 [2] 14 18 }

  condition:
    any of them
}