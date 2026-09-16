rule TTP_XOR_WriteProcessMemory_2f40 {
  strings:
    $key_2f40 = { 78 32 [2] 4a 10 [2] 4c 25 [2] 62 25 [2] 5d 39 }

  condition:
    any of them
}