rule TTP_XOR_WriteProcessMemory_5b55 {
  strings:
    $key_5b55 = { 0c 27 [2] 3e 05 [2] 38 30 [2] 16 30 [2] 29 2c }

  condition:
    any of them
}