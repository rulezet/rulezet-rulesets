rule TTP_XOR_WriteProcessMemory_ffe1 {
  strings:
    $key_ffe1 = { a8 93 [2] 9a b1 [2] 9c 84 [2] b2 84 [2] 8d 98 }

  condition:
    any of them
}