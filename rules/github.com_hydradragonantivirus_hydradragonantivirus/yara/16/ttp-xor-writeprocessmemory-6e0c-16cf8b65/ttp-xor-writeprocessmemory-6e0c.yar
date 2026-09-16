rule TTP_XOR_WriteProcessMemory_6e0c {
  strings:
    $key_6e0c = { 39 7e [2] 0b 5c [2] 0d 69 [2] 23 69 [2] 1c 75 }

  condition:
    any of them
}