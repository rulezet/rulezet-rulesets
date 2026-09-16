rule TTP_XOR_WriteProcessMemory_3e10 {
  strings:
    $key_3e10 = { 69 62 [2] 5b 40 [2] 5d 75 [2] 73 75 [2] 4c 69 }

  condition:
    any of them
}