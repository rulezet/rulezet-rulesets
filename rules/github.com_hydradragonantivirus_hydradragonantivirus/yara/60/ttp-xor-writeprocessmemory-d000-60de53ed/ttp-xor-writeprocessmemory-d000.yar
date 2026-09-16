rule TTP_XOR_WriteProcessMemory_d000 {
  strings:
    $key_d000 = { 87 72 [2] b5 50 [2] b3 65 [2] 9d 65 [2] a2 79 }

  condition:
    any of them
}