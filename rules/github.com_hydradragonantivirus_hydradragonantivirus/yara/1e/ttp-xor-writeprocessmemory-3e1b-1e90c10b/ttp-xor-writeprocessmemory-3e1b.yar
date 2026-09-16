rule TTP_XOR_WriteProcessMemory_3e1b {
  strings:
    $key_3e1b = { 69 69 [2] 5b 4b [2] 5d 7e [2] 73 7e [2] 4c 62 }

  condition:
    any of them
}