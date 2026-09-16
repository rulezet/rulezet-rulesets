rule TTP_XOR_WriteProcessMemory_0e70 {
  strings:
    $key_0e70 = { 59 02 [2] 6b 20 [2] 6d 15 [2] 43 15 [2] 7c 09 }

  condition:
    any of them
}