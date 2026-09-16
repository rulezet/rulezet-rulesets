rule TTP_XOR_WriteProcessMemory_336e {
  strings:
    $key_336e = { 64 1c [2] 56 3e [2] 50 0b [2] 7e 0b [2] 41 17 }

  condition:
    any of them
}