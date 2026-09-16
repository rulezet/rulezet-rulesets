rule TTP_XOR_WriteProcessMemory_d125 {
  strings:
    $key_d125 = { 86 57 [2] b4 75 [2] b2 40 [2] 9c 40 [2] a3 5c }

  condition:
    any of them
}