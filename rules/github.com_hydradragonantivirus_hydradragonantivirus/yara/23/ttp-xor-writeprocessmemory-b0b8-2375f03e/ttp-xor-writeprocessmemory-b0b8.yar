rule TTP_XOR_WriteProcessMemory_b0b8 {
  strings:
    $key_b0b8 = { e7 ca [2] d5 e8 [2] d3 dd [2] fd dd [2] c2 c1 }

  condition:
    any of them
}