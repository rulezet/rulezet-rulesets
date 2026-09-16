rule TTP_XOR_WriteProcessMemory_6e10 {
  strings:
    $key_6e10 = { 39 62 [2] 0b 40 [2] 0d 75 [2] 23 75 [2] 1c 69 }

  condition:
    any of them
}