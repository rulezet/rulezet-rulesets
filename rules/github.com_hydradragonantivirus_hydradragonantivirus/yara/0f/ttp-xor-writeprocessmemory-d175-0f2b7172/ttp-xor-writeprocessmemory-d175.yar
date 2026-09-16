rule TTP_XOR_WriteProcessMemory_d175 {
  strings:
    $key_d175 = { 86 07 [2] b4 25 [2] b2 10 [2] 9c 10 [2] a3 0c }

  condition:
    any of them
}