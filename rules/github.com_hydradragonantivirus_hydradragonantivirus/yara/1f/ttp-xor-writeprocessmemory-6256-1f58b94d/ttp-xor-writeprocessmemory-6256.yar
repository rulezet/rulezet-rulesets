rule TTP_XOR_WriteProcessMemory_6256 {
  strings:
    $key_6256 = { 35 24 [2] 07 06 [2] 01 33 [2] 2f 33 [2] 10 2f }

  condition:
    any of them
}