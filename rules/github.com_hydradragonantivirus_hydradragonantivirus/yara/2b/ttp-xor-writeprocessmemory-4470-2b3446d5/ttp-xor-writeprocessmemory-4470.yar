rule TTP_XOR_WriteProcessMemory_4470 {
  strings:
    $key_4470 = { 13 02 [2] 21 20 [2] 27 15 [2] 09 15 [2] 36 09 }

  condition:
    any of them
}