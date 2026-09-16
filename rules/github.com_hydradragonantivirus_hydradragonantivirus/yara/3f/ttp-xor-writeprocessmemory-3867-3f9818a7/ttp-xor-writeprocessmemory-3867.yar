rule TTP_XOR_WriteProcessMemory_3867 {
  strings:
    $key_3867 = { 6f 15 [2] 5d 37 [2] 5b 02 [2] 75 02 [2] 4a 1e }

  condition:
    any of them
}