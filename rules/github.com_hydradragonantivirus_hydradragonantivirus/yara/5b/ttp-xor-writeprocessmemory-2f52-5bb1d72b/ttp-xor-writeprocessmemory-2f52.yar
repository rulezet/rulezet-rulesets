rule TTP_XOR_WriteProcessMemory_2f52 {
  strings:
    $key_2f52 = { 78 20 [2] 4a 02 [2] 4c 37 [2] 62 37 [2] 5d 2b }

  condition:
    any of them
}