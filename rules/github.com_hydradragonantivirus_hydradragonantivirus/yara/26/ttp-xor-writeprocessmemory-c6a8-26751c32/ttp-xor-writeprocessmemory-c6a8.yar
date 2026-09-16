rule TTP_XOR_WriteProcessMemory_c6a8 {
  strings:
    $key_c6a8 = { 91 da [2] a3 f8 [2] a5 cd [2] 8b cd [2] b4 d1 }

  condition:
    any of them
}