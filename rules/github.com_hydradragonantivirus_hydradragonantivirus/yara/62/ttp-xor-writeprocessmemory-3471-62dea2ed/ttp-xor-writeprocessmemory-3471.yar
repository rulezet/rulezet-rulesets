rule TTP_XOR_WriteProcessMemory_3471 {
  strings:
    $key_3471 = { 63 03 [2] 51 21 [2] 57 14 [2] 79 14 [2] 46 08 }

  condition:
    any of them
}