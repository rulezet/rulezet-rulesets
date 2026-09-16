rule TTP_XOR_WriteProcessMemory_6470 {
  strings:
    $key_6470 = { 33 02 [2] 01 20 [2] 07 15 [2] 29 15 [2] 16 09 }

  condition:
    any of them
}