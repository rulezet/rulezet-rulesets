rule TTP_XOR_WriteProcessMemory_c431 {
  strings:
    $key_c431 = { 93 43 [2] a1 61 [2] a7 54 [2] 89 54 [2] b6 48 }

  condition:
    any of them
}