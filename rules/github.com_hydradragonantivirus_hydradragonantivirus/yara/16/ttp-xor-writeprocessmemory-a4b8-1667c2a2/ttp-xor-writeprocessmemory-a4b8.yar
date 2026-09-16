rule TTP_XOR_WriteProcessMemory_a4b8 {
  strings:
    $key_a4b8 = { f3 ca [2] c1 e8 [2] c7 dd [2] e9 dd [2] d6 c1 }

  condition:
    any of them
}