rule TTP_XOR_WriteProcessMemory_c96e {
  strings:
    $key_c96e = { 9e 1c [2] ac 3e [2] aa 0b [2] 84 0b [2] bb 17 }

  condition:
    any of them
}