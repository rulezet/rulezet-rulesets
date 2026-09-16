rule TTP_XOR_WriteProcessMemory_61eb {
  strings:
    $key_61eb = { 36 99 [2] 04 bb [2] 02 8e [2] 2c 8e [2] 13 92 }

  condition:
    any of them
}