rule TTP_XOR_WriteProcessMemory_b2b8 {
  strings:
    $key_b2b8 = { e5 ca [2] d7 e8 [2] d1 dd [2] ff dd [2] c0 c1 }

  condition:
    any of them
}