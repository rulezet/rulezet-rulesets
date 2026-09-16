rule TTP_XOR_WriteProcessMemory_2b7c {
  strings:
    $key_2b7c = { 7c 0e [2] 4e 2c [2] 48 19 [2] 66 19 [2] 59 05 }

  condition:
    any of them
}