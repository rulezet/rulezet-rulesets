rule TTP_XOR_WriteProcessMemory_506e {
  strings:
    $key_506e = { 07 1c [2] 35 3e [2] 33 0b [2] 1d 0b [2] 22 17 }

  condition:
    any of them
}