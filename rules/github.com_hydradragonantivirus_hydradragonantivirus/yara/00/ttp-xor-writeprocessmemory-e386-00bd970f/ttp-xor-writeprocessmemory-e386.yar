rule TTP_XOR_WriteProcessMemory_e386 {
  strings:
    $key_e386 = { b4 f4 [2] 86 d6 [2] 80 e3 [2] ae e3 [2] 91 ff }

  condition:
    any of them
}