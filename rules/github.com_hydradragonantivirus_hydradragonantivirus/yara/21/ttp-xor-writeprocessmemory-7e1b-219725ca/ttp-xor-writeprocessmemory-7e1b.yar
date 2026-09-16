rule TTP_XOR_WriteProcessMemory_7e1b {
  strings:
    $key_7e1b = { 29 69 [2] 1b 4b [2] 1d 7e [2] 33 7e [2] 0c 62 }

  condition:
    any of them
}