rule TTP_XOR_WriteProcessMemory_4553 {
  strings:
    $key_4553 = { 12 21 [2] 20 03 [2] 26 36 [2] 08 36 [2] 37 2a }

  condition:
    any of them
}