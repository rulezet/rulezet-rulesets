rule TTP_XOR_WriteProcessMemory_456e {
  strings:
    $key_456e = { 12 1c [2] 20 3e [2] 26 0b [2] 08 0b [2] 37 17 }

  condition:
    any of them
}