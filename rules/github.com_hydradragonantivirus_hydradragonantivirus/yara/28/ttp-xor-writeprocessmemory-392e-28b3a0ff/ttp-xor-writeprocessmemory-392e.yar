rule TTP_XOR_WriteProcessMemory_392e {
  strings:
    $key_392e = { 6e 5c [2] 5c 7e [2] 5a 4b [2] 74 4b [2] 4b 57 }

  condition:
    any of them
}