rule TTP_XOR_WriteProcessMemory_d617 {
  strings:
    $key_d617 = { 81 65 [2] b3 47 [2] b5 72 [2] 9b 72 [2] a4 6e }

  condition:
    any of them
}