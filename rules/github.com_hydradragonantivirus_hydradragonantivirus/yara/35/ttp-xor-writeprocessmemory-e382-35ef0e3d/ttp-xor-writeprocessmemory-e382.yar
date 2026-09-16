rule TTP_XOR_WriteProcessMemory_e382 {
  strings:
    $key_e382 = { b4 f0 [2] 86 d2 [2] 80 e7 [2] ae e7 [2] 91 fb }

  condition:
    any of them
}