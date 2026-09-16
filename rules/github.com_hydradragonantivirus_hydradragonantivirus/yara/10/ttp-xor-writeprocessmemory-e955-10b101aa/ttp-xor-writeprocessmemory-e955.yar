rule TTP_XOR_WriteProcessMemory_e955 {
  strings:
    $key_e955 = { be 27 [2] 8c 05 [2] 8a 30 [2] a4 30 [2] 9b 2c }

  condition:
    any of them
}