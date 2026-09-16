rule TTP_XOR_WriteProcessMemory_a795 {
  strings:
    $key_a795 = { f0 e7 [2] c2 c5 [2] c4 f0 [2] ea f0 [2] d5 ec }

  condition:
    any of them
}