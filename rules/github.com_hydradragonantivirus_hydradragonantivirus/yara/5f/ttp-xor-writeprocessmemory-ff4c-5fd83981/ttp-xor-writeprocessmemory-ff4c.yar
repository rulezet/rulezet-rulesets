rule TTP_XOR_WriteProcessMemory_ff4c {
  strings:
    $key_ff4c = { a8 3e [2] 9a 1c [2] 9c 29 [2] b2 29 [2] 8d 35 }

  condition:
    any of them
}