rule TTP_XOR_WriteProcessMemory_f565 {
  strings:
    $key_f565 = { a2 17 [2] 90 35 [2] 96 00 [2] b8 00 [2] 87 1c }

  condition:
    any of them
}