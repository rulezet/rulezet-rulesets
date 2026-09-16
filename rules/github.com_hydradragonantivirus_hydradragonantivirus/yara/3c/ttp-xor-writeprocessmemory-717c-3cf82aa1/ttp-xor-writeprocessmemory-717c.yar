rule TTP_XOR_WriteProcessMemory_717c {
  strings:
    $key_717c = { 26 0e [2] 14 2c [2] 12 19 [2] 3c 19 [2] 03 05 }

  condition:
    any of them
}