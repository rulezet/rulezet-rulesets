rule TTP_XOR_WriteProcessMemory_ff3f {
  strings:
    $key_ff3f = { a8 4d [2] 9a 6f [2] 9c 5a [2] b2 5a [2] 8d 46 }

  condition:
    any of them
}