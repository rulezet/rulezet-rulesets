rule TTP_XOR_WriteProcessMemory_b1b8 {
  strings:
    $key_b1b8 = { e6 ca [2] d4 e8 [2] d2 dd [2] fc dd [2] c3 c1 }

  condition:
    any of them
}