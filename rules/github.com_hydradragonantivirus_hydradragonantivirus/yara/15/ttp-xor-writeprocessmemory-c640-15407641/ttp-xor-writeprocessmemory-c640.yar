rule TTP_XOR_WriteProcessMemory_c640 {
  strings:
    $key_c640 = { 91 32 [2] a3 10 [2] a5 25 [2] 8b 25 [2] b4 39 }

  condition:
    any of them
}