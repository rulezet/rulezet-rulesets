rule TTP_XOR_WriteProcessMemory_3853 {
  strings:
    $key_3853 = { 6f 21 [2] 5d 03 [2] 5b 36 [2] 75 36 [2] 4a 2a }

  condition:
    any of them
}