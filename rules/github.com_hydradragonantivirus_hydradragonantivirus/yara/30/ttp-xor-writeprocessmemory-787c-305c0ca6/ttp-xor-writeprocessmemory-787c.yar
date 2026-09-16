rule TTP_XOR_WriteProcessMemory_787c {
  strings:
    $key_787c = { 2f 0e [2] 1d 2c [2] 1b 19 [2] 35 19 [2] 0a 05 }

  condition:
    any of them
}