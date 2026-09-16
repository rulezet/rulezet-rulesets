rule TTP_XOR_WriteProcessMemory_ff7c {
  strings:
    $key_ff7c = { a8 0e [2] 9a 2c [2] 9c 19 [2] b2 19 [2] 8d 05 }

  condition:
    any of them
}