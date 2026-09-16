rule TTP_XOR_WriteProcessMemory_2e17 {
  strings:
    $key_2e17 = { 79 65 [2] 4b 47 [2] 4d 72 [2] 63 72 [2] 5c 6e }

  condition:
    any of them
}