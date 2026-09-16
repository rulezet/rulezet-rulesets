rule TTP_XOR_WriteProcessMemory_3452 {
  strings:
    $key_3452 = { 63 20 [2] 51 02 [2] 57 37 [2] 79 37 [2] 46 2b }

  condition:
    any of them
}