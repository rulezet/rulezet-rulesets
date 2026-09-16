rule TTP_XOR_WriteProcessMemory_d0c1 {
  strings:
    $key_d0c1 = { 87 b3 [2] b5 91 [2] b3 a4 [2] 9d a4 [2] a2 b8 }

  condition:
    any of them
}