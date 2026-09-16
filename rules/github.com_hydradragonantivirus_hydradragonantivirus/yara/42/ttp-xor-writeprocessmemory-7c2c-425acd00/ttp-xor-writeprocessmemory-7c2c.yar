rule TTP_XOR_WriteProcessMemory_7c2c {
  strings:
    $key_7c2c = { 2b 5e [2] 19 7c [2] 1f 49 [2] 31 49 [2] 0e 55 }

  condition:
    any of them
}