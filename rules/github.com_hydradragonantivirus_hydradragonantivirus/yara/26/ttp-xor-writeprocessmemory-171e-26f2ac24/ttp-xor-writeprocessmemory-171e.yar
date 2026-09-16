rule TTP_XOR_WriteProcessMemory_171e {
  strings:
    $key_171e = { 40 6c [2] 72 4e [2] 74 7b [2] 5a 7b [2] 65 67 }

  condition:
    any of them
}