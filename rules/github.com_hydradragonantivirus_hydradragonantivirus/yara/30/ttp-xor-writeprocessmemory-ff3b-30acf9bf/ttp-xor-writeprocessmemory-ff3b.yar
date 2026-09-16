rule TTP_XOR_WriteProcessMemory_ff3b {
  strings:
    $key_ff3b = { a8 49 [2] 9a 6b [2] 9c 5e [2] b2 5e [2] 8d 42 }

  condition:
    any of them
}