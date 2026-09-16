rule TTP_XOR_WriteProcessMemory_476e {
  strings:
    $key_476e = { 10 1c [2] 22 3e [2] 24 0b [2] 0a 0b [2] 35 17 }

  condition:
    any of them
}