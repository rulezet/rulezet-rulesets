rule TTP_XOR_WriteProcessMemory_7e5b {
  strings:
    $key_7e5b = { 29 29 [2] 1b 0b [2] 1d 3e [2] 33 3e [2] 0c 22 }

  condition:
    any of them
}