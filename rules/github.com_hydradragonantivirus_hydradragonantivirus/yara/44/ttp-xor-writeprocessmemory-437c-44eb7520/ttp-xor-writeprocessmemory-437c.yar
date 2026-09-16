rule TTP_XOR_WriteProcessMemory_437c {
  strings:
    $key_437c = { 14 0e [2] 26 2c [2] 20 19 [2] 0e 19 [2] 31 05 }

  condition:
    any of them
}