rule TTP_XOR_WriteProcessMemory_ff20 {
  strings:
    $key_ff20 = { a8 52 [2] 9a 70 [2] 9c 45 [2] b2 45 [2] 8d 59 }

  condition:
    any of them
}