rule TTP_XOR_WriteProcessMemory_2f70 {
  strings:
    $key_2f70 = { 78 02 [2] 4a 20 [2] 4c 15 [2] 62 15 [2] 5d 09 }

  condition:
    any of them
}