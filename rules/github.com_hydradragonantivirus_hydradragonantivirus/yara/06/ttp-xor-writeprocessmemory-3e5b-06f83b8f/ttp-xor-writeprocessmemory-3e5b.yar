rule TTP_XOR_WriteProcessMemory_3e5b {
  strings:
    $key_3e5b = { 69 29 [2] 5b 0b [2] 5d 3e [2] 73 3e [2] 4c 22 }

  condition:
    any of them
}