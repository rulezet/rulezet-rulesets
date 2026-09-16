rule TTP_XOR_WriteProcessMemory_0a70 {
  strings:
    $key_0a70 = { 5d 02 [2] 6f 20 [2] 69 15 [2] 47 15 [2] 78 09 }

  condition:
    any of them
}