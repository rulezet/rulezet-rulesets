rule TTP_XOR_WriteProcessMemory_ff29 {
  strings:
    $key_ff29 = { a8 5b [2] 9a 79 [2] 9c 4c [2] b2 4c [2] 8d 50 }

  condition:
    any of them
}