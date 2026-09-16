rule TTP_XOR_WriteProcessMemory_c795 {
  strings:
    $key_c795 = { 90 e7 [2] a2 c5 [2] a4 f0 [2] 8a f0 [2] b5 ec }

  condition:
    any of them
}