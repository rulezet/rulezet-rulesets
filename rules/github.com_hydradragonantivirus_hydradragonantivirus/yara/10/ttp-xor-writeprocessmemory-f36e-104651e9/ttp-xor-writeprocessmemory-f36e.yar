rule TTP_XOR_WriteProcessMemory_f36e {
  strings:
    $key_f36e = { a4 1c [2] 96 3e [2] 90 0b [2] be 0b [2] 81 17 }

  condition:
    any of them
}