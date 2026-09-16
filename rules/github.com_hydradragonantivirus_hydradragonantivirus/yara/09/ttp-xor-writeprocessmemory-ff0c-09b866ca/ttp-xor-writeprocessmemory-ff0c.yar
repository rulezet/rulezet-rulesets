rule TTP_XOR_WriteProcessMemory_ff0c {
  strings:
    $key_ff0c = { a8 7e [2] 9a 5c [2] 9c 69 [2] b2 69 [2] 8d 75 }

  condition:
    any of them
}