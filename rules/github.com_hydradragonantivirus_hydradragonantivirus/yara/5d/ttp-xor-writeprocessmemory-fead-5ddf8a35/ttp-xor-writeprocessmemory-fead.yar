rule TTP_XOR_WriteProcessMemory_fead {
  strings:
    $key_fead = { a9 df [2] 9b fd [2] 9d c8 [2] b3 c8 [2] 8c d4 }

  condition:
    any of them
}