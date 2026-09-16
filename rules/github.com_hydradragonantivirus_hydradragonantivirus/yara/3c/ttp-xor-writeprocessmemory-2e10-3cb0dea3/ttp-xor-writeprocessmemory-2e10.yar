rule TTP_XOR_WriteProcessMemory_2e10 {
  strings:
    $key_2e10 = { 79 62 [2] 4b 40 [2] 4d 75 [2] 63 75 [2] 5c 69 }

  condition:
    any of them
}