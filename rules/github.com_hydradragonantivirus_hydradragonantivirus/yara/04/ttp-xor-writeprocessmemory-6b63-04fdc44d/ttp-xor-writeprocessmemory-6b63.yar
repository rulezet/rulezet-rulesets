rule TTP_XOR_WriteProcessMemory_6b63 {
  strings:
    $key_6b63 = { 3c 11 [2] 0e 33 [2] 08 06 [2] 26 06 [2] 19 1a }

  condition:
    any of them
}