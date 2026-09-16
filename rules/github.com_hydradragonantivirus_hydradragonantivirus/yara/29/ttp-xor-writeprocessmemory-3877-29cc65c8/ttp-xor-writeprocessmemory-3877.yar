rule TTP_XOR_WriteProcessMemory_3877 {
  strings:
    $key_3877 = { 6f 05 [2] 5d 27 [2] 5b 12 [2] 75 12 [2] 4a 0e }

  condition:
    any of them
}