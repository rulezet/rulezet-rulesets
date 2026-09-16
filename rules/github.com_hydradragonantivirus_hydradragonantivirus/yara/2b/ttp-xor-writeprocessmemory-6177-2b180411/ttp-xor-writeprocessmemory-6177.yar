rule TTP_XOR_WriteProcessMemory_6177 {
  strings:
    $key_6177 = { 36 05 [2] 04 27 [2] 02 12 [2] 2c 12 [2] 13 0e }

  condition:
    any of them
}