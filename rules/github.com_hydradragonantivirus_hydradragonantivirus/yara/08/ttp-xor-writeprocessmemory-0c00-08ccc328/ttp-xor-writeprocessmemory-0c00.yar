rule TTP_XOR_WriteProcessMemory_0c00 {
  strings:
    $key_0c00 = { 5b 72 [2] 69 50 [2] 6f 65 [2] 41 65 [2] 7e 79 }

  condition:
    any of them
}