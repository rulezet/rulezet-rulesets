rule TTP_XOR_WriteProcessMemory_c120 {
  strings:
    $key_c120 = { 96 52 [2] a4 70 [2] a2 45 [2] 8c 45 [2] b3 59 }

  condition:
    any of them
}