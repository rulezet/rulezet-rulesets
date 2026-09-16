rule TTP_XOR_WriteProcessMemory_ff7f {
  strings:
    $key_ff7f = { a8 0d [2] 9a 2f [2] 9c 1a [2] b2 1a [2] 8d 06 }

  condition:
    any of them
}