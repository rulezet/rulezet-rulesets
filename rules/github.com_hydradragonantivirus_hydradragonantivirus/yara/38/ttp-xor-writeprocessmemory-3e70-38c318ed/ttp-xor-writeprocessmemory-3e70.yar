rule TTP_XOR_WriteProcessMemory_3e70 {
  strings:
    $key_3e70 = { 69 02 [2] 5b 20 [2] 5d 15 [2] 73 15 [2] 4c 09 }

  condition:
    any of them
}