rule TTP_XOR_WriteProcessMemory_2302 {
  strings:
    $key_2302 = { 74 70 [2] 46 52 [2] 40 67 [2] 6e 67 [2] 51 7b }

  condition:
    any of them
}