rule TTP_XOR_WriteProcessMemory_1e6e {
  strings:
    $key_1e6e = { 49 1c [2] 7b 3e [2] 7d 0b [2] 53 0b [2] 6c 17 }

  condition:
    any of them
}