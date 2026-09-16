rule TTP_XOR_WriteProcessMemory_ff18 {
  strings:
    $key_ff18 = { a8 6a [2] 9a 48 [2] 9c 7d [2] b2 7d [2] 8d 61 }

  condition:
    any of them
}