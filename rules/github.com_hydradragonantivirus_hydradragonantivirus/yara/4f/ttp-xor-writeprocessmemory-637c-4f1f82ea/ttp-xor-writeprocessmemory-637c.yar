rule TTP_XOR_WriteProcessMemory_637c {
  strings:
    $key_637c = { 34 0e [2] 06 2c [2] 00 19 [2] 2e 19 [2] 11 05 }

  condition:
    any of them
}