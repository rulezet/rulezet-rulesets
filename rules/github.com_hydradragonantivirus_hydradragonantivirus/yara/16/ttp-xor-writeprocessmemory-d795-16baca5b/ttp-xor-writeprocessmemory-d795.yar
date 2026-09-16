rule TTP_XOR_WriteProcessMemory_d795 {
  strings:
    $key_d795 = { 80 e7 [2] b2 c5 [2] b4 f0 [2] 9a f0 [2] a5 ec }

  condition:
    any of them
}