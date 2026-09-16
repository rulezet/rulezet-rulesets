rule TTP_XOR_WriteProcessMemory_692b {
  strings:
    $key_692b = { 3e 59 [2] 0c 7b [2] 0a 4e [2] 24 4e [2] 1b 52 }

  condition:
    any of them
}