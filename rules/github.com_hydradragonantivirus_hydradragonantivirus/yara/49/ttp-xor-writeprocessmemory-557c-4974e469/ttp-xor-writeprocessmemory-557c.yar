rule TTP_XOR_WriteProcessMemory_557c {
  strings:
    $key_557c = { 02 0e [2] 30 2c [2] 36 19 [2] 18 19 [2] 27 05 }

  condition:
    any of them
}