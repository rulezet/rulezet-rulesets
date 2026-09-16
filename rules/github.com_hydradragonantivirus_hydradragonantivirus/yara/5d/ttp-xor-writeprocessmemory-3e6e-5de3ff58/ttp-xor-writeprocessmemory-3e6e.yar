rule TTP_XOR_WriteProcessMemory_3e6e {
  strings:
    $key_3e6e = { 69 1c [2] 5b 3e [2] 5d 0b [2] 73 0b [2] 4c 17 }

  condition:
    any of them
}