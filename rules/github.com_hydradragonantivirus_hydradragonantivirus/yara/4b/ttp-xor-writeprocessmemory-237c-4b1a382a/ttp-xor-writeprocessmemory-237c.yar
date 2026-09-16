rule TTP_XOR_WriteProcessMemory_237c {
  strings:
    $key_237c = { 74 0e [2] 46 2c [2] 40 19 [2] 6e 19 [2] 51 05 }

  condition:
    any of them
}