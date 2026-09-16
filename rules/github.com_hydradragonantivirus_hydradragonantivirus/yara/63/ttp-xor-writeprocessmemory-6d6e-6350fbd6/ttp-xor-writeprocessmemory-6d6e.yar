rule TTP_XOR_WriteProcessMemory_6d6e {
  strings:
    $key_6d6e = { 3a 1c [2] 08 3e [2] 0e 0b [2] 20 0b [2] 1f 17 }

  condition:
    any of them
}