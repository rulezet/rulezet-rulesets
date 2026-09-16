rule TTP_XOR_WriteProcessMemory_d017 {
  strings:
    $key_d017 = { 87 65 [2] b5 47 [2] b3 72 [2] 9d 72 [2] a2 6e }

  condition:
    any of them
}