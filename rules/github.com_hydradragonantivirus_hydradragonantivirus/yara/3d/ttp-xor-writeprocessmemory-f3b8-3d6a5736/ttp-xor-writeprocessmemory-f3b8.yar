rule TTP_XOR_WriteProcessMemory_f3b8 {
  strings:
    $key_f3b8 = { a4 ca [2] 96 e8 [2] 90 dd [2] be dd [2] 81 c1 }

  condition:
    any of them
}