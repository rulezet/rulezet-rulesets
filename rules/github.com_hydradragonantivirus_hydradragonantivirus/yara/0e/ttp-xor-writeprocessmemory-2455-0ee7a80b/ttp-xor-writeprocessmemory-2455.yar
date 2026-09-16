rule TTP_XOR_WriteProcessMemory_2455 {
  strings:
    $key_2455 = { 73 27 [2] 41 05 [2] 47 30 [2] 69 30 [2] 56 2c }

  condition:
    any of them
}