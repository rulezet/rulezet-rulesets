rule TTP_XOR_WriteProcessMemory_4b7c {
  strings:
    $key_4b7c = { 1c 0e [2] 2e 2c [2] 28 19 [2] 06 19 [2] 39 05 }

  condition:
    any of them
}