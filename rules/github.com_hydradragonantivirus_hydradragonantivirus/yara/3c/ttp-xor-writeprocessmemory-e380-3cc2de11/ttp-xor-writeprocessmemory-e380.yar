rule TTP_XOR_WriteProcessMemory_e380 {
  strings:
    $key_e380 = { b4 f2 [2] 86 d0 [2] 80 e5 [2] ae e5 [2] 91 f9 }

  condition:
    any of them
}