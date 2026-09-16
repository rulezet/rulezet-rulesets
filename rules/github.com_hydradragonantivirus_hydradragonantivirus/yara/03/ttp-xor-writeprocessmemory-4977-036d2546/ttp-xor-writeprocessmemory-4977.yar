rule TTP_XOR_WriteProcessMemory_4977 {
  strings:
    $key_4977 = { 1e 05 [2] 2c 27 [2] 2a 12 [2] 04 12 [2] 3b 0e }

  condition:
    any of them
}