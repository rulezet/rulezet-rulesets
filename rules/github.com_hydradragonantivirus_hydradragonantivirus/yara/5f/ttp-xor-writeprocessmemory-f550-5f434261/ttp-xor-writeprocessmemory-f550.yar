rule TTP_XOR_WriteProcessMemory_f550 {
  strings:
    $key_f550 = { a2 22 [2] 90 00 [2] 96 35 [2] b8 35 [2] 87 29 }

  condition:
    any of them
}