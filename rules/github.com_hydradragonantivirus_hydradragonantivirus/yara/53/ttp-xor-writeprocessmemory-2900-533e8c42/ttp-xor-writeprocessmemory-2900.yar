rule TTP_XOR_WriteProcessMemory_2900 {
  strings:
    $key_2900 = { 7e 72 [2] 4c 50 [2] 4a 65 [2] 64 65 [2] 5b 79 }

  condition:
    any of them
}