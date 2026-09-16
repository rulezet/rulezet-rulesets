rule TTP_XOR_WriteProcessMemory_fe95 {
  strings:
    $key_fe95 = { a9 e7 [2] 9b c5 [2] 9d f0 [2] b3 f0 [2] 8c ec }

  condition:
    any of them
}