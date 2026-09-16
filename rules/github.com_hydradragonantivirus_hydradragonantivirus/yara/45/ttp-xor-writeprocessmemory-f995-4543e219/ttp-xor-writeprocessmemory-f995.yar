rule TTP_XOR_WriteProcessMemory_f995 {
  strings:
    $key_f995 = { ae e7 [2] 9c c5 [2] 9a f0 [2] b4 f0 [2] 8b ec }

  condition:
    any of them
}