rule TTP_XOR_WriteProcessMemory_2f51 {
  strings:
    $key_2f51 = { 78 23 [2] 4a 01 [2] 4c 34 [2] 62 34 [2] 5d 28 }

  condition:
    any of them
}