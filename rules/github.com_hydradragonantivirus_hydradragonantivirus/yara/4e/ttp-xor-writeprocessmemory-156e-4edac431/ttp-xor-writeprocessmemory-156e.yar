rule TTP_XOR_WriteProcessMemory_156e {
  strings:
    $key_156e = { 42 1c [2] 70 3e [2] 76 0b [2] 58 0b [2] 67 17 }

  condition:
    any of them
}