rule TTP_XOR_WriteProcessMemory_2ea7 {
  strings:
    $key_2ea7 = { 79 d5 [2] 4b f7 [2] 4d c2 [2] 63 c2 [2] 5c de }

  condition:
    any of them
}