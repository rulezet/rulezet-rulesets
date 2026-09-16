rule TTP_XOR_WriteProcessMemory_21b8 {
  strings:
    $key_21b8 = { 76 ca [2] 44 e8 [2] 42 dd [2] 6c dd [2] 53 c1 }

  condition:
    any of them
}