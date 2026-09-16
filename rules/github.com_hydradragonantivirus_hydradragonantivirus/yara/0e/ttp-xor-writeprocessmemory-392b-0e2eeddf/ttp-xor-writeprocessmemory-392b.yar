rule TTP_XOR_WriteProcessMemory_392b {
  strings:
    $key_392b = { 6e 59 [2] 5c 7b [2] 5a 4e [2] 74 4e [2] 4b 52 }

  condition:
    any of them
}