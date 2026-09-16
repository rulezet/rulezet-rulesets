rule TTP_XOR_WriteProcessMemory_0c6e {
  strings:
    $key_0c6e = { 5b 1c [2] 69 3e [2] 6f 0b [2] 41 0b [2] 7e 17 }

  condition:
    any of them
}