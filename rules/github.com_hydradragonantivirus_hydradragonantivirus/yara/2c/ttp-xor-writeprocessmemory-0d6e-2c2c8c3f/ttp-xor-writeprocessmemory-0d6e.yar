rule TTP_XOR_WriteProcessMemory_0d6e {
  strings:
    $key_0d6e = { 5a 1c [2] 68 3e [2] 6e 0b [2] 40 0b [2] 7f 17 }

  condition:
    any of them
}