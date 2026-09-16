rule TTP_XOR_WriteProcessMemory_556e {
  strings:
    $key_556e = { 02 1c [2] 30 3e [2] 36 0b [2] 18 0b [2] 27 17 }

  condition:
    any of them
}