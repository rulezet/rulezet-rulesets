rule TTP_XOR_WriteProcessMemory_efe1 {
  strings:
    $key_efe1 = { b8 93 [2] 8a b1 [2] 8c 84 [2] a2 84 [2] 9d 98 }

  condition:
    any of them
}