rule TTP_XOR_WriteProcessMemory_2b55 {
  strings:
    $key_2b55 = { 7c 27 [2] 4e 05 [2] 48 30 [2] 66 30 [2] 59 2c }

  condition:
    any of them
}