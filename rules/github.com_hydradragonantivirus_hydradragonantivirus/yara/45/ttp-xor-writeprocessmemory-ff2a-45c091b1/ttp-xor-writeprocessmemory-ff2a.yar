rule TTP_XOR_WriteProcessMemory_ff2a {
  strings:
    $key_ff2a = { a8 58 [2] 9a 7a [2] 9c 4f [2] b2 4f [2] 8d 53 }

  condition:
    any of them
}