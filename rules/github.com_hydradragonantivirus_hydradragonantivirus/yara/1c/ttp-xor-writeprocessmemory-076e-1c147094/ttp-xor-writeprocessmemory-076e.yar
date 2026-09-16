rule TTP_XOR_WriteProcessMemory_076e {
  strings:
    $key_076e = { 50 1c [2] 62 3e [2] 64 0b [2] 4a 0b [2] 75 17 }

  condition:
    any of them
}