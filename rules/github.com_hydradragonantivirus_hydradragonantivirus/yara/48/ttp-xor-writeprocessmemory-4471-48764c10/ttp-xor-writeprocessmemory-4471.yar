rule TTP_XOR_WriteProcessMemory_4471 {
  strings:
    $key_4471 = { 13 03 [2] 21 21 [2] 27 14 [2] 09 14 [2] 36 08 }

  condition:
    any of them
}