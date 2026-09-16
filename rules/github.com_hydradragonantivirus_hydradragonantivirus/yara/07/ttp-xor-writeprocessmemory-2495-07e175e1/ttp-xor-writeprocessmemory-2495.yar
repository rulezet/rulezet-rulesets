rule TTP_XOR_WriteProcessMemory_2495 {
  strings:
    $key_2495 = { 73 e7 [2] 41 c5 [2] 47 f0 [2] 69 f0 [2] 56 ec }

  condition:
    any of them
}