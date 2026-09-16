rule TTP_XOR_WriteProcessMemory_4e6e {
  strings:
    $key_4e6e = { 19 1c [2] 2b 3e [2] 2d 0b [2] 03 0b [2] 3c 17 }

  condition:
    any of them
}