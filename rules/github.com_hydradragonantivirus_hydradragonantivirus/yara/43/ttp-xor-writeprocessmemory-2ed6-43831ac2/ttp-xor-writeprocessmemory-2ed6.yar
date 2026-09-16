rule TTP_XOR_WriteProcessMemory_2ed6 {
  strings:
    $key_2ed6 = { 79 a4 [2] 4b 86 [2] 4d b3 [2] 63 b3 [2] 5c af }

  condition:
    any of them
}