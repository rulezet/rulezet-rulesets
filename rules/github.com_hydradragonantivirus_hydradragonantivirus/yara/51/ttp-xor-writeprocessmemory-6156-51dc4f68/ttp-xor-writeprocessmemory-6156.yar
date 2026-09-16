rule TTP_XOR_WriteProcessMemory_6156 {
  strings:
    $key_6156 = { 36 24 [2] 04 06 [2] 02 33 [2] 2c 33 [2] 13 2f }

  condition:
    any of them
}