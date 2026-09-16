rule TTP_XOR_WriteProcessMemory_2e53 {
  strings:
    $key_2e53 = { 79 21 [2] 4b 03 [2] 4d 36 [2] 63 36 [2] 5c 2a }

  condition:
    any of them
}