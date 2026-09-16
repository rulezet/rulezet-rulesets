rule TTP_XOR_WriteProcessMemory_ff69 {
  strings:
    $key_ff69 = { a8 1b [2] 9a 39 [2] 9c 0c [2] b2 0c [2] 8d 10 }

  condition:
    any of them
}