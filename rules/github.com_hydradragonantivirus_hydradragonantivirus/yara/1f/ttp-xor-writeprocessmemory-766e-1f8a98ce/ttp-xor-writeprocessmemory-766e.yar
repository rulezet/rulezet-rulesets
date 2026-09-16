rule TTP_XOR_WriteProcessMemory_766e {
  strings:
    $key_766e = { 21 1c [2] 13 3e [2] 15 0b [2] 3b 0b [2] 04 17 }

  condition:
    any of them
}