rule TTP_XOR_WriteProcessMemory_137c {
  strings:
    $key_137c = { 44 0e [2] 76 2c [2] 70 19 [2] 5e 19 [2] 61 05 }

  condition:
    any of them
}