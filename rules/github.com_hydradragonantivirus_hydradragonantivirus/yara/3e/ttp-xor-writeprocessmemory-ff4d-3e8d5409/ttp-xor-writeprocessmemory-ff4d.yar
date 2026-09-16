rule TTP_XOR_WriteProcessMemory_ff4d {
  strings:
    $key_ff4d = { a8 3f [2] 9a 1d [2] 9c 28 [2] b2 28 [2] 8d 34 }

  condition:
    any of them
}