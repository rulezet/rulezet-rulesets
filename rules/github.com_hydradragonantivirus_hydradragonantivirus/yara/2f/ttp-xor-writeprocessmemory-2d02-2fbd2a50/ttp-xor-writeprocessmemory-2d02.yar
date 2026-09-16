rule TTP_XOR_WriteProcessMemory_2d02 {
  strings:
    $key_2d02 = { 7a 70 [2] 48 52 [2] 4e 67 [2] 60 67 [2] 5f 7b }

  condition:
    any of them
}