rule TTP_XOR_WriteProcessMemory_6472 {
  strings:
    $key_6472 = { 33 00 [2] 01 22 [2] 07 17 [2] 29 17 [2] 16 0b }

  condition:
    any of them
}