rule TTP_XOR_WriteProcessMemory_6123 {
  strings:
    $key_6123 = { 36 51 [2] 04 73 [2] 02 46 [2] 2c 46 [2] 13 5a }

  condition:
    any of them
}