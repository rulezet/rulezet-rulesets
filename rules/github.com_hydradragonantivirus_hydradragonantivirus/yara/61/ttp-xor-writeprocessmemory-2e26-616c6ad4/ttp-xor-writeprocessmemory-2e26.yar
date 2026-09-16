rule TTP_XOR_WriteProcessMemory_2e26 {
  strings:
    $key_2e26 = { 79 54 [2] 4b 76 [2] 4d 43 [2] 63 43 [2] 5c 5f }

  condition:
    any of them
}