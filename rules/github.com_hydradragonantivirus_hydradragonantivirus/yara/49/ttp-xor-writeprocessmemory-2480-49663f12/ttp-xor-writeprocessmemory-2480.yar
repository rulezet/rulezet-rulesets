rule TTP_XOR_WriteProcessMemory_2480 {
  strings:
    $key_2480 = { 73 f2 [2] 41 d0 [2] 47 e5 [2] 69 e5 [2] 56 f9 }

  condition:
    any of them
}