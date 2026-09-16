rule TTP_XOR_WriteProcessMemory_6e11 {
  strings:
    $key_6e11 = { 39 63 [2] 0b 41 [2] 0d 74 [2] 23 74 [2] 1c 68 }

  condition:
    any of them
}