rule TTP_XOR_WriteProcessMemory_ff5a {
  strings:
    $key_ff5a = { a8 28 [2] 9a 0a [2] 9c 3f [2] b2 3f [2] 8d 23 }

  condition:
    any of them
}