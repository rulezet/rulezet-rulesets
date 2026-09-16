rule TTP_XOR_WriteProcessMemory_d165 {
  strings:
    $key_d165 = { 86 17 [2] b4 35 [2] b2 00 [2] 9c 00 [2] a3 1c }

  condition:
    any of them
}