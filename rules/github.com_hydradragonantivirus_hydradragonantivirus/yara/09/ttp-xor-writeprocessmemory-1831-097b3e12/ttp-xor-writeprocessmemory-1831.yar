rule TTP_XOR_WriteProcessMemory_1831 {
  strings:
    $key_1831 = { 4f 43 [2] 7d 61 [2] 7b 54 [2] 55 54 [2] 6a 48 }

  condition:
    any of them
}