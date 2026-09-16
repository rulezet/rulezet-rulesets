rule TTP_XOR_WriteProcessMemory_610c {
  strings:
    $key_610c = { 36 7e [2] 04 5c [2] 02 69 [2] 2c 69 [2] 13 75 }

  condition:
    any of them
}