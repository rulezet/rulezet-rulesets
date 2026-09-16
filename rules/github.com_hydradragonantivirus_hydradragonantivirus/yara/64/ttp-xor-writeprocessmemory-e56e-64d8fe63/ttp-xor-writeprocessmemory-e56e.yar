rule TTP_XOR_WriteProcessMemory_e56e {
  strings:
    $key_e56e = { b2 1c [2] 80 3e [2] 86 0b [2] a8 0b [2] 97 17 }

  condition:
    any of them
}