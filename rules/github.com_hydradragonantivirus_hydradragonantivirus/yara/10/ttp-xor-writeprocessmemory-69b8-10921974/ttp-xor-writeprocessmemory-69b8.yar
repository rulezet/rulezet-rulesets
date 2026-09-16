rule TTP_XOR_WriteProcessMemory_69b8 {
  strings:
    $key_69b8 = { 3e ca [2] 0c e8 [2] 0a dd [2] 24 dd [2] 1b c1 }

  condition:
    any of them
}