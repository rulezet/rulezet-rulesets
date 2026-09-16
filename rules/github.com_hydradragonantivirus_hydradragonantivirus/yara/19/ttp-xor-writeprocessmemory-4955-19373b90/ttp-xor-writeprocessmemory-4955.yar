rule TTP_XOR_WriteProcessMemory_4955 {
  strings:
    $key_4955 = { 1e 27 [2] 2c 05 [2] 2a 30 [2] 04 30 [2] 3b 2c }

  condition:
    any of them
}