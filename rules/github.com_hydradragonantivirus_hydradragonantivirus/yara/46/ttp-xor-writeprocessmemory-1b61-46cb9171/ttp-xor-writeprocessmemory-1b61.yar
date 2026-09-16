rule TTP_XOR_WriteProcessMemory_1b61 {
  strings:
    $key_1b61 = { 4c 13 [2] 7e 31 [2] 78 04 [2] 56 04 [2] 69 18 }

  condition:
    any of them
}