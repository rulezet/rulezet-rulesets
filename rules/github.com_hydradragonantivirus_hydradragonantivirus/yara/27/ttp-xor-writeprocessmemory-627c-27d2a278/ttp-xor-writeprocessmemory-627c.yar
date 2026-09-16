rule TTP_XOR_WriteProcessMemory_627c {
  strings:
    $key_627c = { 35 0e [2] 07 2c [2] 01 19 [2] 2f 19 [2] 10 05 }

  condition:
    any of them
}