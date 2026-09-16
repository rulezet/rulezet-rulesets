rule TTP_XOR_WriteProcessMemory_a5b8 {
  strings:
    $key_a5b8 = { f2 ca [2] c0 e8 [2] c6 dd [2] e8 dd [2] d7 c1 }

  condition:
    any of them
}