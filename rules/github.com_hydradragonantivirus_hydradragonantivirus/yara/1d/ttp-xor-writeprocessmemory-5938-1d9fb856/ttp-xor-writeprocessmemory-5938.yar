rule TTP_XOR_WriteProcessMemory_5938 {
  strings:
    $key_5938 = { 0e 4a [2] 3c 68 [2] 3a 5d [2] 14 5d [2] 2b 41 }

  condition:
    any of them
}