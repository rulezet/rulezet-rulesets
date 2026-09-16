rule TTP_XOR_WriteProcessMemory_1877 {
  strings:
    $key_1877 = { 4f 05 [2] 7d 27 [2] 7b 12 [2] 55 12 [2] 6a 0e }

  condition:
    any of them
}