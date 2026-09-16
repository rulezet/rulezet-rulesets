rule TTP_XOR_WriteProcessMemory_dca8 {
  strings:
    $key_dca8 = { 8b da [2] b9 f8 [2] bf cd [2] 91 cd [2] ae d1 }

  condition:
    any of them
}