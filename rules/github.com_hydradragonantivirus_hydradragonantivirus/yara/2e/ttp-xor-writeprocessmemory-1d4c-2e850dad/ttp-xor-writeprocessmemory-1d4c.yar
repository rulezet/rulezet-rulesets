rule TTP_XOR_WriteProcessMemory_1d4c {
  strings:
    $key_1d4c = { 4a 3e [2] 78 1c [2] 7e 29 [2] 50 29 [2] 6f 35 }

  condition:
    any of them
}