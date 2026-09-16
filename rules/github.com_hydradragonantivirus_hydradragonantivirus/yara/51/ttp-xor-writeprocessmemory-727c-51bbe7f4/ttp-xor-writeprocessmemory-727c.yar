rule TTP_XOR_WriteProcessMemory_727c {
  strings:
    $key_727c = { 25 0e [2] 17 2c [2] 11 19 [2] 3f 19 [2] 00 05 }

  condition:
    any of them
}