rule TTP_XOR_WriteProcessMemory_ff19 {
  strings:
    $key_ff19 = { a8 6b [2] 9a 49 [2] 9c 7c [2] b2 7c [2] 8d 60 }

  condition:
    any of them
}