rule TTP_XOR_WriteProcessMemory_ff2f {
  strings:
    $key_ff2f = { a8 5d [2] 9a 7f [2] 9c 4a [2] b2 4a [2] 8d 56 }

  condition:
    any of them
}