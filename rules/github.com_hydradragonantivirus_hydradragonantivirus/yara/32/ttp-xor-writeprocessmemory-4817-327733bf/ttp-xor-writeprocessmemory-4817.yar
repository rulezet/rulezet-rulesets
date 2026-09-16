rule TTP_XOR_WriteProcessMemory_4817 {
  strings:
    $key_4817 = { 1f 65 [2] 2d 47 [2] 2b 72 [2] 05 72 [2] 3a 6e }

  condition:
    any of them
}