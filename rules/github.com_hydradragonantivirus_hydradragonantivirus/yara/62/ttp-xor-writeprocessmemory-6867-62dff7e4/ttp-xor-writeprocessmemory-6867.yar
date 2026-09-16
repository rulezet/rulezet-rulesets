rule TTP_XOR_WriteProcessMemory_6867 {
  strings:
    $key_6867 = { 3f 15 [2] 0d 37 [2] 0b 02 [2] 25 02 [2] 1a 1e }

  condition:
    any of them
}