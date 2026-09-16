rule TTP_XOR_WriteProcessMemory_d325 {
  strings:
    $key_d325 = { 84 57 [2] b6 75 [2] b0 40 [2] 9e 40 [2] a1 5c }

  condition:
    any of them
}