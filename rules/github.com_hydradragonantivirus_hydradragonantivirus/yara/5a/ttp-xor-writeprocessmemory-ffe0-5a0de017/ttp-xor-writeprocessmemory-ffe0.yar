rule TTP_XOR_WriteProcessMemory_ffe0 {
  strings:
    $key_ffe0 = { a8 92 [2] 9a b0 [2] 9c 85 [2] b2 85 [2] 8d 99 }

  condition:
    any of them
}