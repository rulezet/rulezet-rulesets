rule TTP_XOR_WriteProcessMemory_6e20 {
  strings:
    $key_6e20 = { 39 52 [2] 0b 70 [2] 0d 45 [2] 23 45 [2] 1c 59 }

  condition:
    any of them
}