rule TTP_XOR_WriteProcessMemory_1955 {
  strings:
    $key_1955 = { 4e 27 [2] 7c 05 [2] 7a 30 [2] 54 30 [2] 6b 2c }

  condition:
    any of them
}