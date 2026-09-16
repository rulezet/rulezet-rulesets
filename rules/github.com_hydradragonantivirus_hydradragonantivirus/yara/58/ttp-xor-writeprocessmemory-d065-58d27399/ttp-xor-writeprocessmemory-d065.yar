rule TTP_XOR_WriteProcessMemory_d065 {
  strings:
    $key_d065 = { 87 17 [2] b5 35 [2] b3 00 [2] 9d 00 [2] a2 1c }

  condition:
    any of them
}