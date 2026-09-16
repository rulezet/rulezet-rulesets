rule TTP_XOR_WriteProcessMemory_f52e {
  strings:
    $key_f52e = { a2 5c [2] 90 7e [2] 96 4b [2] b8 4b [2] 87 57 }

  condition:
    any of them
}