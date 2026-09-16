rule TTP_XOR_WriteProcessMemory_4131 {
  strings:
    $key_4131 = { 16 43 [2] 24 61 [2] 22 54 [2] 0c 54 [2] 33 48 }

  condition:
    any of them
}