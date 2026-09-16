rule TTP_XOR_WriteProcessMemory_fff1 {
  strings:
    $key_fff1 = { a8 83 [2] 9a a1 [2] 9c 94 [2] b2 94 [2] 8d 88 }

  condition:
    any of them
}