rule TTP_XOR_WriteProcessMemory_19b8 {
  strings:
    $key_19b8 = { 4e ca [2] 7c e8 [2] 7a dd [2] 54 dd [2] 6b c1 }

  condition:
    any of them
}