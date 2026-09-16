rule TTP_XOR_WriteProcessMemory_c95e {
  strings:
    $key_c95e = { 9e 2c [2] ac 0e [2] aa 3b [2] 84 3b [2] bb 27 }

  condition:
    any of them
}