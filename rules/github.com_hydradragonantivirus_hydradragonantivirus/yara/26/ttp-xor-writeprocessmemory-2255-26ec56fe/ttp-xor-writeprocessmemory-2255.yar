rule TTP_XOR_WriteProcessMemory_2255 {
  strings:
    $key_2255 = { 75 27 [2] 47 05 [2] 41 30 [2] 6f 30 [2] 50 2c }

  condition:
    any of them
}