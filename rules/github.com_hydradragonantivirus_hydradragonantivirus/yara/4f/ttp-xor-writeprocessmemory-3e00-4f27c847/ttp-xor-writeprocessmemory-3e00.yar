rule TTP_XOR_WriteProcessMemory_3e00 {
  strings:
    $key_3e00 = { 69 72 [2] 5b 50 [2] 5d 65 [2] 73 65 [2] 4c 79 }

  condition:
    any of them
}