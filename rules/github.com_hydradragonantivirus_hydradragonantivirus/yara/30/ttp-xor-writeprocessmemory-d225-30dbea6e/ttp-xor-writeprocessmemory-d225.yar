rule TTP_XOR_WriteProcessMemory_d225 {
  strings:
    $key_d225 = { 85 57 [2] b7 75 [2] b1 40 [2] 9f 40 [2] a0 5c }

  condition:
    any of them
}