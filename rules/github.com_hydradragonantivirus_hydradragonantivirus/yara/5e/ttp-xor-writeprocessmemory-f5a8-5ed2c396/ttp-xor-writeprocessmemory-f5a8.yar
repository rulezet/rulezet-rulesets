rule TTP_XOR_WriteProcessMemory_f5a8 {
  strings:
    $key_f5a8 = { a2 da [2] 90 f8 [2] 96 cd [2] b8 cd [2] 87 d1 }

  condition:
    any of them
}