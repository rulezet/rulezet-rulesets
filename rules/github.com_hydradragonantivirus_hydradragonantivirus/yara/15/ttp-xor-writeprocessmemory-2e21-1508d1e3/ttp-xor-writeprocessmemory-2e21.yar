rule TTP_XOR_WriteProcessMemory_2e21 {
  strings:
    $key_2e21 = { 79 53 [2] 4b 71 [2] 4d 44 [2] 63 44 [2] 5c 58 }

  condition:
    any of them
}