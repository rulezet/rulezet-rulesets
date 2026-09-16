rule TTP_XOR_WriteProcessMemory_61e3 {
  strings:
    $key_61e3 = { 36 91 [2] 04 b3 [2] 02 86 [2] 2c 86 [2] 13 9a }

  condition:
    any of them
}