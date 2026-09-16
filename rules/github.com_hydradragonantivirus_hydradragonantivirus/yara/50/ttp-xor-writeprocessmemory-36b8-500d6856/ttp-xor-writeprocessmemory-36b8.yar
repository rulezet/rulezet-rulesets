rule TTP_XOR_WriteProcessMemory_36b8 {
  strings:
    $key_36b8 = { 61 ca [2] 53 e8 [2] 55 dd [2] 7b dd [2] 44 c1 }

  condition:
    any of them
}