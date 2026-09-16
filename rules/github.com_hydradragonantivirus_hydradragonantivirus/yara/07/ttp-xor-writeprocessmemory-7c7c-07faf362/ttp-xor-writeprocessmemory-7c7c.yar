rule TTP_XOR_WriteProcessMemory_7c7c {
  strings:
    $key_7c7c = { 2b 0e [2] 19 2c [2] 1f 19 [2] 31 19 [2] 0e 05 }

  condition:
    any of them
}