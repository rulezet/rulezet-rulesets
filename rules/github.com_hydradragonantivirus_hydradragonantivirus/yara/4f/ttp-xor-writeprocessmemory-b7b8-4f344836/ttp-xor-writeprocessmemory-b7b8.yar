rule TTP_XOR_WriteProcessMemory_b7b8 {
  strings:
    $key_b7b8 = { e0 ca [2] d2 e8 [2] d4 dd [2] fa dd [2] c5 c1 }

  condition:
    any of them
}