rule TTP_XOR_WriteProcessMemory_1010 {
  strings:
    $key_1010 = { 47 62 [2] 75 40 [2] 73 75 [2] 5d 75 [2] 62 69 }

  condition:
    any of them
}