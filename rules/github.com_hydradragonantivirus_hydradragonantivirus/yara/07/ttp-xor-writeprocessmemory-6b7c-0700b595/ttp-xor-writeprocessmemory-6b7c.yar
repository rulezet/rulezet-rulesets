rule TTP_XOR_WriteProcessMemory_6b7c {
  strings:
    $key_6b7c = { 3c 0e [2] 0e 2c [2] 08 19 [2] 26 19 [2] 19 05 }

  condition:
    any of them
}