rule TTP_XOR_WriteProcessMemory_f7a8 {
  strings:
    $key_f7a8 = { a0 da [2] 92 f8 [2] 94 cd [2] ba cd [2] 85 d1 }

  condition:
    any of them
}