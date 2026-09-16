rule TTP_XOR_WriteProcessMemory_0255 {
  strings:
    $key_0255 = { 55 27 [2] 67 05 [2] 61 30 [2] 4f 30 [2] 70 2c }

  condition:
    any of them
}