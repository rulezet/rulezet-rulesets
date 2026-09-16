rule TTP_XOR_WriteProcessMemory_3e72 {
  strings:
    $key_3e72 = { 69 00 [2] 5b 22 [2] 5d 17 [2] 73 17 [2] 4c 0b }

  condition:
    any of them
}