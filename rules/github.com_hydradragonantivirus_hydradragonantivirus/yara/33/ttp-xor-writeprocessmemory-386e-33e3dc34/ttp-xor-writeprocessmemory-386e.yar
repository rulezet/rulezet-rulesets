rule TTP_XOR_WriteProcessMemory_386e {
  strings:
    $key_386e = { 6f 1c [2] 5d 3e [2] 5b 0b [2] 75 0b [2] 4a 17 }

  condition:
    any of them
}