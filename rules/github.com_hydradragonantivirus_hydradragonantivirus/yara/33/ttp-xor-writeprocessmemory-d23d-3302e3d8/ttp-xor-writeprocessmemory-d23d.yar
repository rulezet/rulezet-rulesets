rule TTP_XOR_WriteProcessMemory_d23d {
  strings:
    $key_d23d = { 85 4f [2] b7 6d [2] b1 58 [2] 9f 58 [2] a0 44 }

  condition:
    any of them
}