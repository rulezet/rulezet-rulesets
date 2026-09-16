rule TTP_XOR_WriteProcessMemory_1b60 {
  strings:
    $key_1b60 = { 4c 12 [2] 7e 30 [2] 78 05 [2] 56 05 [2] 69 19 }

  condition:
    any of them
}