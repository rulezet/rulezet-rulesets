rule TTP_XOR_WriteProcessMemory_1470 {
  strings:
    $key_1470 = { 43 02 [2] 71 20 [2] 77 15 [2] 59 15 [2] 66 09 }

  condition:
    any of them
}