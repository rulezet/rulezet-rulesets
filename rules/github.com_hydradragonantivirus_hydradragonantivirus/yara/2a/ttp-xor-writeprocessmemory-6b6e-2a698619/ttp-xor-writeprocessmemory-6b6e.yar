rule TTP_XOR_WriteProcessMemory_6b6e {
  strings:
    $key_6b6e = { 3c 1c [2] 0e 3e [2] 08 0b [2] 26 0b [2] 19 17 }

  condition:
    any of them
}