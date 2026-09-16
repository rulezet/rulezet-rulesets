rule TTP_XOR_WriteProcessMemory_c7a8 {
  strings:
    $key_c7a8 = { 90 da [2] a2 f8 [2] a4 cd [2] 8a cd [2] b5 d1 }

  condition:
    any of them
}