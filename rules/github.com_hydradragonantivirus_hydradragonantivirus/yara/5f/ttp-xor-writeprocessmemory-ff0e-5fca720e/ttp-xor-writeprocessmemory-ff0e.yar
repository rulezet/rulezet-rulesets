rule TTP_XOR_WriteProcessMemory_ff0e {
  strings:
    $key_ff0e = { a8 7c [2] 9a 5e [2] 9c 6b [2] b2 6b [2] 8d 77 }

  condition:
    any of them
}