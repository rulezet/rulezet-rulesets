rule TTP_XOR_WriteProcessMemory_ff48 {
  strings:
    $key_ff48 = { a8 3a [2] 9a 18 [2] 9c 2d [2] b2 2d [2] 8d 31 }

  condition:
    any of them
}