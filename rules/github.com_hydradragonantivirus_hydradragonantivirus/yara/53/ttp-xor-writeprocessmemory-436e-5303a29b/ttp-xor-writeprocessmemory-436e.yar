rule TTP_XOR_WriteProcessMemory_436e {
  strings:
    $key_436e = { 14 1c [2] 26 3e [2] 20 0b [2] 0e 0b [2] 31 17 }

  condition:
    any of them
}