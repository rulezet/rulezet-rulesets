rule TTP_XOR_WriteProcessMemory_ff1e {
  strings:
    $key_ff1e = { a8 6c [2] 9a 4e [2] 9c 7b [2] b2 7b [2] 8d 67 }

  condition:
    any of them
}