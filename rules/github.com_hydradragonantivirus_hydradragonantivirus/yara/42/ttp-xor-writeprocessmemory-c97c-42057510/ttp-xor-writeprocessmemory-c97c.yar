rule TTP_XOR_WriteProcessMemory_c97c {
  strings:
    $key_c97c = { 9e 0e [2] ac 2c [2] aa 19 [2] 84 19 [2] bb 05 }

  condition:
    any of them
}