rule TTP_XOR_WriteProcessMemory_c225 {
  strings:
    $key_c225 = { 95 57 [2] a7 75 [2] a1 40 [2] 8f 40 [2] b0 5c }

  condition:
    any of them
}