rule TTP_XOR_WriteProcessMemory_2e00 {
  strings:
    $key_2e00 = { 79 72 [2] 4b 50 [2] 4d 65 [2] 63 65 [2] 5c 79 }

  condition:
    any of them
}