rule TTP_XOR_WriteProcessMemory_ff4a {
  strings:
    $key_ff4a = { a8 38 [2] 9a 1a [2] 9c 2f [2] b2 2f [2] 8d 33 }

  condition:
    any of them
}