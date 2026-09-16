rule TTP_XOR_WriteProcessMemory_e595 {
  strings:
    $key_e595 = { b2 e7 [2] 80 c5 [2] 86 f0 [2] a8 f0 [2] 97 ec }

  condition:
    any of them
}