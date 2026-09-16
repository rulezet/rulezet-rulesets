rule TTP_XOR_WriteProcessMemory_ff7e {
  strings:
    $key_ff7e = { a8 0c [2] 9a 2e [2] 9c 1b [2] b2 1b [2] 8d 07 }

  condition:
    any of them
}